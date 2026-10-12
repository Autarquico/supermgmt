package github

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/autarquico/supermgmt/internal/providers/github/ghfake"
)

type rootTestClock struct{ now time.Time }

func (c *rootTestClock) Now() time.Time { return c.now }

func (c *rootTestClock) advance(d time.Duration) { c.now = c.now.Add(d) }

// rootTestRepo stands in for a TUF repository publishing trusted_root.json.
type rootTestRepo struct {
	doc   []byte
	down  bool
	calls int
}

func (r *rootTestRepo) fetch(TUFSource) ([]byte, error) {
	r.calls++
	if r.down {
		return nil, errors.New("tuf repository unreachable")
	}
	return r.doc, nil
}

func rootTestSetup(t *testing.T, dir string) (*TrustRoots, *rootTestRepo, *rootTestClock) {
	t.Helper()
	clock := &rootTestClock{now: time.Date(2026, 10, 12, 9, 0, 0, 0, time.UTC)}
	repo := &rootTestRepo{doc: ghfake.NewSigstore(t).TrustedRootJSON(t)}
	roots := rootTestRoots(dir, clock, repo)
	return roots, repo, clock
}

func rootTestRoots(dir string, clock *rootTestClock, repo *rootTestRepo) *TrustRoots {
	roots := NewTrustRoots(TrustRootsConfig{
		CacheDir: dir, Sources: []TUFSource{{Name: "sigstore"}}, Clock: clock,
		RefreshEvery: 24 * time.Hour, MaxAge: 7 * 24 * time.Hour,
	})
	roots.fetch = repo.fetch
	return roots
}

func rootTestMaterials(t *testing.T, roots *TrustRoots) {
	t.Helper()
	got, err := roots.Materials()
	if err != nil || len(got) != 1 {
		t.Fatalf("materials = %d, err = %v", len(got), err)
	}
}

func rootTestStale(t *testing.T, roots *TrustRoots) {
	t.Helper()
	if _, err := roots.Materials(); !errors.Is(err, ErrTrustRootStale) {
		t.Fatalf("err = %v; want ErrTrustRootStale", err)
	}
}

func TestTrustRoots_RefreshesOnlyWhenDue(t *testing.T) {
	roots, repo, clock := rootTestSetup(t, t.TempDir())
	rootTestMaterials(t, roots)
	clock.advance(23 * time.Hour)
	rootTestMaterials(t, roots)
	if repo.calls != 1 {
		t.Fatalf("fetches within the refresh period = %d; want 1", repo.calls)
	}
	clock.advance(2 * time.Hour)
	rootTestMaterials(t, roots)
	if repo.calls != 2 {
		t.Errorf("fetches after the refresh period = %d; want 2", repo.calls)
	}
}

func TestTrustRoots_FailedRefreshServesLastGoodWithinMaxAge(t *testing.T) {
	roots, repo, clock := rootTestSetup(t, t.TempDir())
	rootTestMaterials(t, roots)
	repo.down = true
	clock.advance(48 * time.Hour)
	rootTestMaterials(t, roots)
	rootTestMaterials(t, roots)
	if repo.calls != 2 {
		t.Errorf("fetches = %d; want 2 (the failed refresh is not retried on every call)", repo.calls)
	}
	clock.advance(rootRetryEvery)
	rootTestMaterials(t, roots)
	if repo.calls != 3 {
		t.Errorf("fetches after the retry delay = %d; want 3", repo.calls)
	}
}

func TestTrustRoots_FailedRefreshFailsClosedBeyondMaxAge(t *testing.T) {
	roots, repo, clock := rootTestSetup(t, t.TempDir())
	rootTestMaterials(t, roots)
	repo.down = true
	clock.advance(7*24*time.Hour + time.Minute)
	rootTestStale(t, roots)
}

func TestTrustRoots_NothingCachedAndUnreachableFailsClosed(t *testing.T) {
	roots, repo, _ := rootTestSetup(t, t.TempDir())
	repo.down = true
	rootTestStale(t, roots)
}

func TestTrustRoots_LastGoodSurvivesARestart(t *testing.T) {
	dir := t.TempDir()
	first, repo, clock := rootTestSetup(t, dir)
	rootTestMaterials(t, first)

	repo.down = true
	clock.advance(3 * 24 * time.Hour)
	rootTestMaterials(t, rootTestRoots(dir, clock, repo))

	clock.advance(5 * 24 * time.Hour)
	rootTestStale(t, rootTestRoots(dir, clock, repo))
}

func TestTrustRoots_RefusesAnUnusableRootAndKeepsTheLastGood(t *testing.T) {
	roots, repo, clock := rootTestSetup(t, t.TempDir())
	rootTestMaterials(t, roots)
	repo.doc = []byte(`{"mediaType":"not a trusted root"`)
	clock.advance(25 * time.Hour)
	rootTestMaterials(t, roots)

	empty, brokenRepo, _ := rootTestSetup(t, t.TempDir())
	brokenRepo.doc = []byte("garbage")
	rootTestStale(t, empty)
}

func TestTrustRoots_UnreadableCacheIsNoCache(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "sigstore.trusted_root.json"), []byte("{broken"), 0o600); err != nil {
		t.Fatal(err)
	}
	roots, repo, _ := rootTestSetup(t, dir)
	rootTestMaterials(t, roots)
	if repo.calls != 1 {
		t.Errorf("fetches = %d; want 1", repo.calls)
	}
}

func TestTrustRoots_CacheFutureDatedIsNotTrusted(t *testing.T) {
	dir := t.TempDir()
	first, repo, clock := rootTestSetup(t, dir)
	rootTestMaterials(t, first)

	repo.down = true
	clock.advance(-time.Hour)
	rootTestStale(t, rootTestRoots(dir, clock, repo))
}

func TestTrustRoots_EverySourceMustBeVouchedFor(t *testing.T) {
	clock := &rootTestClock{now: time.Date(2026, 10, 12, 9, 0, 0, 0, time.UTC)}
	doc := ghfake.NewSigstore(t).TrustedRootJSON(t)
	roots := NewTrustRoots(TrustRootsConfig{
		CacheDir: t.TempDir(), Clock: clock,
		Sources: []TUFSource{{Name: "sigstore"}, {Name: "github"}},
	})
	roots.fetch = func(src TUFSource) ([]byte, error) {
		if src.Name == "github" {
			return nil, errors.New("github tuf unreachable")
		}
		return doc, nil
	}
	_, err := roots.Materials()
	if !errors.Is(err, ErrTrustRootStale) {
		t.Fatalf("err = %v; want ErrTrustRootStale", err)
	}
}

func TestTrustRoots_TUFOverNetguardRefusesPrivateRepositories(t *testing.T) {
	src := PublicGoodSource()
	src.BaseURL = "https://127.0.0.1:1"
	roots := NewTrustRoots(TrustRootsConfig{
		CacheDir: t.TempDir(), Sources: []TUFSource{src}, Timeout: 2 * time.Second,
		Clock: &rootTestClock{now: time.Date(2026, 10, 12, 9, 0, 0, 0, time.UTC)},
	})
	rootTestStale(t, roots)
}

func TestSources_CarryTheirAnchors(t *testing.T) {
	for _, src := range []TUFSource{PublicGoodSource(), GitHubSource()} {
		if src.Name == "" || src.BaseURL == "" || len(src.Anchor) == 0 {
			t.Errorf("source %+v is incomplete", src)
		}
	}
	if PublicGoodSource().Name == GitHubSource().Name {
		t.Error("sources must not share a cache file")
	}
}
