package github

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/sigstore/sigstore-go/pkg/root"
	"github.com/sigstore/sigstore-go/pkg/tuf"
	"github.com/theupdateframework/go-tuf/v2/metadata/fetcher"

	"github.com/autarquico/supermgmt/internal/domain"
	"github.com/autarquico/supermgmt/internal/netguard"
)

const (
	trustedRootTarget = "trusted_root.json"
	maxTUFBody        = 8 << 20
	maxTrustedRoot    = 1 << 20

	defaultRootRefresh = 24 * time.Hour
	defaultRootMaxAge  = 7 * 24 * time.Hour
	rootRetryEvery     = 10 * time.Minute
)

// ErrTrustRootStale means a trusted root could not be refreshed and the last
// good copy is missing, unreadable or older than the accepted age. Attestation
// verification fails closed; it never falls back to "unverified" (ADR-0028).
var ErrTrustRootStale = errors.New("github: sigstore trusted root is stale")

// TUFSource is one TUF repository publishing a Sigstore trusted root: the
// public-good instance or GitHub's own (private repositories).
type TUFSource struct {
	Name    string // cache file name; unique per source
	BaseURL string
	Anchor  []byte // root.json the TUF chain starts from, embedded at build
}

// PublicGoodSource is the Sigstore public-good instance, anchored at the root
// embedded in sigstore-go.
func PublicGoodSource() TUFSource {
	return TUFSource{Name: "sigstore", BaseURL: tuf.DefaultMirror, Anchor: tuf.DefaultRoot()}
}

// GitHubSource is GitHub's Sigstore instance, anchored at version 1 of its
// TUF root (see githubTUFAnchor).
func GitHubSource() TUFSource {
	return TUFSource{Name: "github", BaseURL: "https://tuf-repo.github.com", Anchor: []byte(githubTUFAnchor)}
}

// RootMaterials yields the trusted materials an attestation may be verified
// against, or an error when they cannot be vouched for.
type RootMaterials interface {
	Materials() ([]root.TrustedMaterial, error)
}

// StaticRoots is a fixed set of trusted materials.
type StaticRoots []root.TrustedMaterial

// Materials returns the fixed set.
func (s StaticRoots) Materials() ([]root.TrustedMaterial, error) { return s, nil }

// TrustRootsConfig configures TrustRoots. Zero RefreshEvery, MaxAge and
// Timeout take their defaults (24h, 7 days, 30s).
type TrustRootsConfig struct {
	// CacheDir holds the TUF metadata and the last good trusted root of each
	// source.
	CacheDir string
	Sources  []TUFSource
	Clock    domain.Clock
	// RefreshEvery is how often a root is refreshed; MaxAge is how old the
	// last good copy may be when a refresh fails.
	RefreshEvery time.Duration
	MaxAge       time.Duration
	Timeout      time.Duration
	// Netguard holds client options; tests pass netguard.WithTestDialer.
	Netguard []netguard.Option
}

// TrustRoots keeps the Sigstore trusted roots fresh: TUF-refreshed over
// netguard (public destinations only, no redirects), last good copy cached on
// disk. A root that cannot be refreshed and whose cached copy is older than
// the accepted age is an error, not a pass.
type TrustRoots struct {
	sources      []TUFSource
	cacheDir     string
	clock        domain.Clock
	refreshEvery time.Duration
	maxAge       time.Duration
	fetch        func(src TUFSource) ([]byte, error)

	mu     sync.Mutex
	loaded map[string]*loadedRoot
}

type loadedRoot struct {
	material    root.TrustedMaterial
	fetchedAt   time.Time
	attemptedAt time.Time
}

// NewTrustRoots serves the configured sources.
func NewTrustRoots(cfg TrustRootsConfig) *TrustRoots {
	r := &TrustRoots{
		sources: cfg.Sources, cacheDir: cfg.CacheDir, clock: cfg.Clock,
		refreshEvery: orDefault(cfg.RefreshEvery, defaultRootRefresh),
		maxAge:       orDefault(cfg.MaxAge, defaultRootMaxAge),
		loaded:       map[string]*loadedRoot{},
	}
	hc := netguard.NewClient(netguard.Allow{}, nil, orDefault(cfg.Timeout, defaultTimeout), maxTUFBody, cfg.Netguard...)
	over := fetcher.NewDefaultFetcher()
	over.SetHTTPClient(hc)
	tufCache := filepath.Join(cfg.CacheDir, "tuf")
	r.fetch = func(src TUFSource) ([]byte, error) { return fetchTrustedRootOverTUF(src, tufCache, over) }
	return r
}

func orDefault(d, fallback time.Duration) time.Duration {
	if d <= 0 {
		return fallback
	}
	return d
}

// Materials returns one trusted material per source, refreshing those due. Any
// source that cannot be vouched for fails the call with ErrTrustRootStale.
func (r *TrustRoots) Materials() ([]root.TrustedMaterial, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	materials := make([]root.TrustedMaterial, 0, len(r.sources))
	for _, src := range r.sources {
		m, err := r.materialOf(src)
		if err != nil {
			return nil, fmt.Errorf("%w: %s: %w", ErrTrustRootStale, src.Name, err)
		}
		materials = append(materials, m)
	}
	return materials, nil
}

func (r *TrustRoots) materialOf(src TUFSource) (root.TrustedMaterial, error) {
	cur := r.loaded[src.Name]
	if cur == nil {
		cur = r.readCache(src)
	}
	now := r.clock.Now()
	if cur != nil && r.fresh(cur, now) {
		return cur.material, nil
	}
	if cur != nil && r.usable(cur, now) && now.Sub(cur.attemptedAt) < rootRetryEvery {
		return cur.material, nil
	}
	fetched, err := r.refresh(src, now)
	if err == nil {
		r.loaded[src.Name] = fetched
		return fetched.material, nil
	}
	if cur != nil && r.usable(cur, now) {
		cur.attemptedAt = now
		r.loaded[src.Name] = cur
		return cur.material, nil
	}
	return nil, fmt.Errorf("cannot refresh and no cached root within %s: %w", r.maxAge, err)
}

func (r *TrustRoots) fresh(l *loadedRoot, now time.Time) bool {
	age := now.Sub(l.fetchedAt)
	return age >= 0 && age < r.refreshEvery
}

func (r *TrustRoots) usable(l *loadedRoot, now time.Time) bool {
	age := now.Sub(l.fetchedAt)
	return age >= 0 && age <= r.maxAge
}

func (r *TrustRoots) refresh(src TUFSource, now time.Time) (*loadedRoot, error) {
	raw, err := r.fetch(src)
	if err != nil {
		return nil, err
	}
	material, err := root.NewTrustedRootFromJSON(raw)
	if err != nil {
		return nil, fmt.Errorf("unusable trusted root: %w", err)
	}
	// A cache that cannot be written costs the offline fallback, not safety.
	_ = r.writeCache(src, raw, now)
	return &loadedRoot{material: material, fetchedAt: now, attemptedAt: now}, nil
}

type cachedRoot struct {
	FetchedAt   time.Time       `json:"fetched_at"`
	TrustedRoot json.RawMessage `json:"trusted_root"`
}

func (r *TrustRoots) cachePath(src TUFSource) string {
	return filepath.Join(r.cacheDir, src.Name+".trusted_root.json")
}

func (r *TrustRoots) writeCache(src TUFSource, raw []byte, now time.Time) error {
	doc, err := json.Marshal(cachedRoot{FetchedAt: now, TrustedRoot: raw})
	if err != nil {
		return err
	}
	if err := os.MkdirAll(r.cacheDir, 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(r.cacheDir, src.Name+".*.tmp")
	if err != nil {
		return err
	}
	_, werr := tmp.Write(doc)
	cerr := tmp.Close()
	if err := errors.Join(werr, cerr); err != nil {
		_ = os.Remove(tmp.Name())
		return err
	}
	if err := os.Rename(tmp.Name(), r.cachePath(src)); err != nil {
		_ = os.Remove(tmp.Name())
		return err
	}
	return nil
}

// readCache returns the last good root of src, or nil when there is none or it
// is unreadable (an unreadable cache is no cache).
func (r *TrustRoots) readCache(src TUFSource) *loadedRoot {
	data, err := os.ReadFile(r.cachePath(src))
	if err != nil {
		return nil
	}
	var doc cachedRoot
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil
	}
	material, err := root.NewTrustedRootFromJSON(doc.TrustedRoot)
	if err != nil {
		return nil
	}
	return &loadedRoot{material: material, fetchedAt: doc.FetchedAt}
}

func fetchTrustedRootOverTUF(src TUFSource, cachePath string, over fetcher.Fetcher) ([]byte, error) {
	opts := tuf.DefaultOptions().
		WithRoot(src.Anchor).
		WithRepositoryBaseURL(src.BaseURL).
		WithCachePath(cachePath).
		WithFetcher(over)
	client, err := tuf.New(opts)
	if err != nil {
		return nil, fmt.Errorf("tuf client for %s: %w", src.BaseURL, err)
	}
	raw, err := client.GetTarget(trustedRootTarget)
	if err != nil {
		return nil, fmt.Errorf("tuf target %s from %s: %w", trustedRootTarget, src.BaseURL, err)
	}
	if len(raw) > maxTrustedRoot {
		return nil, fmt.Errorf("tuf target %s from %s: too large", trustedRootTarget, src.BaseURL)
	}
	return raw, nil
}

// githubTUFAnchor is version 1 of the root.json of https://tuf-repo.github.com,
// fetched from https://tuf-repo.github.com/1.root.json on 2026-10-12
// (sha256 b73aa59b16d2c4989de18e402e168183d0e58f8cf9249d7cb4dd0d1774830c6e).
// It is expired by design: TUF clients walk the root chain forward from it.
// Compare it with the root GitHub publishes before a release (manual check).
const githubTUFAnchor = `{
 "signatures": [
  {
   "keyid": "a10513a5ab61acd0c6b6fbe0504856ead18f3b17c4fabbe3fa848c79a5a187cf",
   "sig": "304402203c8f5f7443f7052923e82f9ca0b1bb61a33498444076a2f43e1285a47f6e562d022014de99a7e5413440896b6804944e3c49390cfe6e617211b8dc42a8e67675bc13"
  },
  {
   "keyid": "d6a89e23fb22801a0d1186bf1bdd007e228f65a8aa9964d24d06cb5fbb0ce91c",
   "sig": "3044022009a20307f974af7e05cc9564eea497f45062e3b21272d1062713b3d22c868298022059d032ad973a28bdbd03959cf96b21398b6b6e2ca618c17ce6c13712246343a2"
  },
  {
   "keyid": "539dde44014c850fe6eeb8b299eb7dae2e1f4bf83454b949e98aa73542cdc65a",
   "sig": "3045022100edd270d36d0c8468b9a1f2ef1c81a270c72ffd50c65bca0ed1ebd424df09f64b022002b27ffafd7bc5bdfc25281b5b9b597cf2d67d4eeb4af2ff45eb3e666b860c21"
  },
  {
   "keyid": "88737ccdac7b49cc237e9aaead81be2a40278b886a693d8149a19cf543f093d3",
   "sig": "30460221008d7d95434e576d5876b2db30fd645505ca546618bbc7a8e4b39f64e6a36df9ad022100c00a5294e4ddd02d48d28918b87a06bdfdeccd0618ecdcec29bb2597a05fe474"
  },
  {
   "keyid": "5e01c9a0b2641a8965a4a74e7df0bc7b2d8278a2c3ca0cf7a3f2f783d3c69800",
   "sig": "30450220215fb3d19d94560a3a2a6067a71c92daf867d13700c9500c4c32d8009a48a634022100df9fb6cee786313bf6c363daac4de39b3dd531f211f81d2391c41bd2d0f91a80"
  },
  {
   "keyid": "4f4d1dd75f2d7f3860e3a068d7bed90dec5f0faafcbe1ace7fb7d95d29e07228",
   "sig": "304502204091ac5e61b6462d262ecc8442781dd09843bed39942a95a4884c8c6a2c212ef022100dcee86392748f48950d04d539ac1a6643ed1f0b4bd6856f8aeb5a135826c846f"
  },
  {
   "keyid": "eb8eff37f93af2faaba519f341decec3cecd3eeafcace32966db9723842c8a62",
   "sig": "30460221009188548601a43b501223caeefca4876ae892e18a85c885004b4c8aeeb05a4421022100abdcc72d94597f8297d6297897ff96f285168dbe6b3d57f846dbc7a2948d2935"
  },
  {
   "keyid": "8b498a80a1b7af188c10c9abdf6aade81d14faaffcde2abcd6063baa673ebd12",
   "sig": "3046022100b440561545d48759dc4140cda9f8af7c9405a101d6136dd0a26edd6562b7064f022100cafa917ed90350494e47d226b64a8ec63ef5ceebb8ba4d2dec2ce018e4ad402a"
  }
 ],
 "signed": {
  "_type": "root",
  "consistent_snapshot": true,
  "expires": "2024-06-23T08:29:18Z",
  "keys": {
   "4f4d1dd75f2d7f3860e3a068d7bed90dec5f0faafcbe1ace7fb7d95d29e07228": {
    "keytype": "ecdsa",
    "keyval": {
     "public": "-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAENki7aZVips5SgRzCd/Om0CGzQKY/\nnv84giqVDmdwb2ys82Z6soFLasvYYEEQcwqaC170n9gr93wHUgPc796uJA==\n-----END PUBLIC KEY-----\n"
    },
    "scheme": "ecdsa-sha2-nistp256",
    "x-tuf-on-ci-keyowner": "@ashtom"
   },
   "539dde44014c850fe6eeb8b299eb7dae2e1f4bf83454b949e98aa73542cdc65a": {
    "keytype": "ecdsa",
    "keyval": {
     "public": "-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAElD0o2sOZN9n3RKQ7PtMLAoXj+2Ai\nn4PKT/pfnzDlNLrD3VTQwCc4sR4t+OLu4KQ+qk+kXkR9YuBsu3bdJZ1OWw==\n-----END PUBLIC KEY-----\n"
    },
    "scheme": "ecdsa-sha2-nistp256",
    "x-tuf-on-ci-keyowner": "@nerdneha"
   },
   "5e01c9a0b2641a8965a4a74e7df0bc7b2d8278a2c3ca0cf7a3f2f783d3c69800": {
    "keytype": "ecdsa",
    "keyval": {
     "public": "-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEC9RNAsuDCNO6T7qA7Y5F8orw2tIW\nr7rUr4ffxvzTMrbkVtjR/trtE0q0+T0zQ8TWLyI6EYMwb947ej2ItfkOyA==\n-----END PUBLIC KEY-----\n"
    },
    "scheme": "ecdsa-sha2-nistp256",
    "x-tuf-on-ci-keyowner": "@jacobdepriest"
   },
   "88737ccdac7b49cc237e9aaead81be2a40278b886a693d8149a19cf543f093d3": {
    "keytype": "ecdsa",
    "keyval": {
     "public": "-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEBagkskNOpOTbetTX5CdnvMy+LiWn\nonRrNrqAHL4WgiebH7Uig7GLhC3bkeA/qgb926/vr9qhOPG9Buj2HatrPw==\n-----END PUBLIC KEY-----\n"
    },
    "scheme": "ecdsa-sha2-nistp256",
    "x-tuf-on-ci-keyowner": "@gregose"
   },
   "8b498a80a1b7af188c10c9abdf6aade81d14faaffcde2abcd6063baa673ebd12": {
    "keytype": "ecdsa",
    "keyval": {
     "public": "-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE7IEoVNwrprchXGhT5sAhSax7SOd3\n8duuISghCzfmHdKJWSbV2wJRamRiUVRtmA83K/qm5cT20WXMCT5QeM/D3A==\n-----END PUBLIC KEY-----\n"
    },
    "scheme": "ecdsa-sha2-nistp256",
    "x-tuf-on-ci-keyowner": "@trevrosen"
   },
   "a10513a5ab61acd0c6b6fbe0504856ead18f3b17c4fabbe3fa848c79a5a187cf": {
    "keytype": "ecdsa",
    "keyval": {
     "public": "-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEC2wJ3xscyXxBLybJ9FVjwkyQMe53\nRHUz77AjMO8MzVaT8xw6ZvJqdNZiytYtigWULlINxw6frNsWJKb/f7lC8A==\n-----END PUBLIC KEY-----\n"
    },
    "scheme": "ecdsa-sha2-nistp256",
    "x-tuf-on-ci-keyowner": "@kommendorkapten"
   },
   "d6a89e23fb22801a0d1186bf1bdd007e228f65a8aa9964d24d06cb5fbb0ce91c": {
    "keytype": "ecdsa",
    "keyval": {
     "public": "-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEDdORwcruW3gqAgaLjH/nNdGMB4kQ\nAvA+wD6DyO4P/wR8ee2ce83NZHq1ZADKhve0rlYKaKy3CqyQ5SmlZ36Zhw==\n-----END PUBLIC KEY-----\n"
    },
    "scheme": "ecdsa-sha2-nistp256",
    "x-tuf-on-ci-keyowner": "@krukow"
   },
   "eb8eff37f93af2faaba519f341decec3cecd3eeafcace32966db9723842c8a62": {
    "keytype": "ecdsa",
    "keyval": {
     "public": "-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAENynVdQnM9h7xU71G7PiJpQaDemub\nkbjsjYwLlPJTQVuxQO8WeIpJf8MEh5rf01t2dDIuCsZ5gRx+QvDv0UzfsA==\n-----END PUBLIC KEY-----\n"
    },
    "scheme": "ecdsa-sha2-nistp256",
    "x-tuf-on-ci-keyowner": "@mph4"
   },
   "eb9799b483affac9da87ef4c9ea467928415c961349e607e5e6e485679b07f8f": {
    "keytype": "ecdsa",
    "keyval": {
     "public": "-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAENKNcNcX+d73lS1TRFb9Vnp8JvOoh\nzYQ+in43iGenbG8RGo9L/6FJ2hoRbVU6xskvyuErcdPbCdI4GxrQ5i8hkw==\n-----END PUBLIC KEY-----\n"
    },
    "scheme": "ecdsa-sha2-nistp256",
    "x-tuf-on-ci-online-uri": "azurekms://production-tuf-root.vault.azure.net/keys/Online-Key/aaf375fd8ed24acb949a5cc173700b05"
   }
  },
  "roles": {
   "root": {
    "keyids": [
     "a10513a5ab61acd0c6b6fbe0504856ead18f3b17c4fabbe3fa848c79a5a187cf",
     "4f4d1dd75f2d7f3860e3a068d7bed90dec5f0faafcbe1ace7fb7d95d29e07228",
     "88737ccdac7b49cc237e9aaead81be2a40278b886a693d8149a19cf543f093d3",
     "5e01c9a0b2641a8965a4a74e7df0bc7b2d8278a2c3ca0cf7a3f2f783d3c69800",
     "d6a89e23fb22801a0d1186bf1bdd007e228f65a8aa9964d24d06cb5fbb0ce91c",
     "eb8eff37f93af2faaba519f341decec3cecd3eeafcace32966db9723842c8a62",
     "8b498a80a1b7af188c10c9abdf6aade81d14faaffcde2abcd6063baa673ebd12",
     "539dde44014c850fe6eeb8b299eb7dae2e1f4bf83454b949e98aa73542cdc65a"
    ],
    "threshold": 3
   },
   "snapshot": {
    "keyids": [
     "eb9799b483affac9da87ef4c9ea467928415c961349e607e5e6e485679b07f8f"
    ],
    "threshold": 1,
    "x-tuf-on-ci-expiry-period": 21,
    "x-tuf-on-ci-signing-period": 7
   },
   "targets": {
    "keyids": [
     "a10513a5ab61acd0c6b6fbe0504856ead18f3b17c4fabbe3fa848c79a5a187cf",
     "4f4d1dd75f2d7f3860e3a068d7bed90dec5f0faafcbe1ace7fb7d95d29e07228",
     "88737ccdac7b49cc237e9aaead81be2a40278b886a693d8149a19cf543f093d3",
     "5e01c9a0b2641a8965a4a74e7df0bc7b2d8278a2c3ca0cf7a3f2f783d3c69800",
     "d6a89e23fb22801a0d1186bf1bdd007e228f65a8aa9964d24d06cb5fbb0ce91c",
     "eb8eff37f93af2faaba519f341decec3cecd3eeafcace32966db9723842c8a62",
     "8b498a80a1b7af188c10c9abdf6aade81d14faaffcde2abcd6063baa673ebd12",
     "539dde44014c850fe6eeb8b299eb7dae2e1f4bf83454b949e98aa73542cdc65a"
    ],
    "threshold": 3
   },
   "timestamp": {
    "keyids": [
     "eb9799b483affac9da87ef4c9ea467928415c961349e607e5e6e485679b07f8f"
    ],
    "threshold": 1,
    "x-tuf-on-ci-expiry-period": 7,
    "x-tuf-on-ci-signing-period": 6
   }
  },
  "spec_version": "1.0.31",
  "version": 1,
  "x-tuf-on-ci-expiry-period": 240,
  "x-tuf-on-ci-signing-period": 60
 }
}`
