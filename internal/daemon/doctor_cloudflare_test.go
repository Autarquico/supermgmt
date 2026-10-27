package daemon

import (
	"context"
	"crypto/x509"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/autarquico/supermgmt/internal/api/wire"
	"github.com/autarquico/supermgmt/internal/audit"
	"github.com/autarquico/supermgmt/internal/config"
	"github.com/autarquico/supermgmt/internal/database"
	"github.com/autarquico/supermgmt/internal/domain"
	smerr "github.com/autarquico/supermgmt/internal/errors"
	"github.com/autarquico/supermgmt/internal/netguard"
	"github.com/autarquico/supermgmt/internal/providers/cloudflare"
	"github.com/autarquico/supermgmt/internal/providers/cloudflare/cffake"
	"github.com/autarquico/supermgmt/internal/secrets"
	"github.com/autarquico/supermgmt/internal/transport/ssh"
)

// secretShelf is the secret store as the doctor reads it.
type secretShelf struct {
	mu   sync.Mutex
	vals map[string]audit.Secret
}

func (s *secretShelf) Get(_ context.Context, ref secrets.Ref) (audit.Secret, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	v, ok := s.vals[ref.Name]
	if !ok {
		return "", smerr.New(smerr.CodeNotFound, "", "secret not found")
	}
	return v, nil
}

func (s *secretShelf) Put(_ context.Context, name string, v audit.Secret, _ map[string]any) (secrets.Ref, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.vals[name] = v
	return secrets.Ref{Name: name}, nil
}

type cloudflareBox struct {
	*doctorBox
	cf      *cffake.Fake
	shelf   *secretShelf
	cfg     config.Cloudflare
	locate  func() (string, error)
	pool    *x509.CertPool
	nodeSeq int
}

func newCloudflareBox(t *testing.T) *cloudflareBox {
	t.Helper()
	box := newDoctorBox(t)
	cf := cffake.New(t, cffake.WithClock(box.clock.Now))
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(cf.CAPEM())
	shelf := &secretShelf{vals: map[string]audit.Secret{
		"cloudflare/api-token":            audit.Secret(cf.Token()),
		"cloudflare/access-service-token": "id.access:secret",
	}}
	return &cloudflareBox{
		doctorBox: box, cf: cf, shelf: shelf, pool: pool,
		cfg: config.Cloudflare{
			AccountID: cffake.DefaultAccountID, Zone: cffake.DefaultZone,
			APITokenRef: config.DefaultCloudflareAPITokenRef, AccessTokenRef: config.DefaultCloudflareAccessTokenRef,
			OwnerEmails: []string{"owner@example.test"},
		},
		locate: func() (string, error) { return "/usr/local/bin/cloudflared", nil },
	}
}

func (c *cloudflareBox) doctor(online bool) CloudflareDoctor {
	d := CloudflareDoctor{Config: c.cfg, Now: c.clock.Now(), DB: c.b.db.Reader(), Locate: c.locate}
	if online {
		d.Secrets = c.shelf
		d.NewProber = func(token audit.Secret) (CloudflareProber, error) {
			return cloudflare.New(c.cf.Endpoint(), c.cfg.AccountID, token,
				cloudflare.WithNetguardOptions(netguard.WithRootCAs(c.pool), netguard.WithTestDialer(c.cf.Dial)))
		}
	}
	return d
}

func (c *cloudflareBox) addNode(name string, transport domain.Transport) domain.Node {
	c.t.Helper()
	var node domain.Node
	err := c.b.db.WithWriteTx(context.Background(), func(ctx context.Context, tx *database.Tx) error {
		c.nodeSeq++
		var err error
		node, err = database.CreateNode(ctx, tx, domain.Node{
			ID: domain.UUIDv7Generator{}.NewID(), ProviderID: c.pve.ID, NativeID: name, Name: name, Kind: "ssh",
			ManagementState: domain.ManagementManaged, Reachability: domain.ReachabilityUnknown,
			Endpoint:  domain.NodeEndpoint{Host: "192.0.2.1", Port: 22, User: "root", Transport: transport, TunnelHostname: tunnelHostnameFor(name, transport)},
			CreatedAt: c.startAt, UpdatedAt: c.startAt,
		})
		return err
	})
	if err != nil {
		c.t.Fatal(err)
	}
	return node
}

func tunnelHostnameFor(name string, transport domain.Transport) string {
	if transport != domain.TransportCloudflare {
		return ""
	}
	return "ssh-" + name + "." + cffake.DefaultZone
}

func (c *cloudflareBox) startOperation(node domain.Node, kind database.TunnelOperationKind, advanceTo database.TunnelPhase) database.TunnelOperation {
	c.t.Helper()
	var op database.TunnelOperation
	err := c.b.db.WithWriteTx(context.Background(), func(ctx context.Context, tx *database.Tx) error {
		var err error
		op, err = database.CreateTunnelOperation(ctx, tx, database.TunnelOperation{
			ID: domain.UUIDv7Generator{}.NewID(), NodeID: node.ID, Kind: kind, AccountID: c.cfg.AccountID,
			Zone: c.cfg.Zone, InstanceID: "instance", Hostname: "ssh-" + node.Name + "." + c.cfg.Zone, CreatedAt: c.startAt,
		})
		if err != nil || advanceTo == database.PhaseStarted {
			return err
		}
		op, err = database.AdvanceTunnelPhase(ctx, tx, op.ID, op.Generation, database.PhaseStarted, advanceTo, database.TunnelObjects{}, c.startAt)
		return err
	})
	if err != nil {
		c.t.Fatal(err)
	}
	return op
}

func (c *cloudflareBox) haltOperation(op database.TunnelOperation, halt database.TunnelPhase) {
	c.t.Helper()
	err := c.b.db.WithWriteTx(context.Background(), func(ctx context.Context, tx *database.Tx) error {
		_, err := database.HaltTunnelOperation(ctx, tx, op.ID, op.Generation, op.Phase, halt, "boom", c.startAt)
		return err
	})
	if err != nil {
		c.t.Fatal(err)
	}
}

func (c *cloudflareBox) recordServiceToken(expires time.Time) {
	c.t.Helper()
	err := c.b.db.WithWriteTx(context.Background(), func(ctx context.Context, tx *database.Tx) error {
		_, err := database.SaveCloudflareState(ctx, tx, database.CloudflareState{
			AccountID: c.cfg.AccountID,
			Token:     database.CloudflareToken{ID: "token-1", Name: "supermgmt-instance", CreatedAt: c.startAt, ExpiresAt: expires},
		}, 0, c.startAt)
		return err
	})
	if err != nil {
		c.t.Fatal(err)
	}
}

func checkNamed(t *testing.T, checks []wire.DoctorCheck, name string) wire.DoctorCheck {
	t.Helper()
	for _, c := range checks {
		if c.Name == name {
			return c
		}
	}
	t.Fatalf("no %s check among %v", name, checks)
	return wire.DoctorCheck{}
}

func TestDoctorCloudflaredIsFoundOrFailsWithHowToInstallIt(t *testing.T) {
	tests := []struct {
		name       string
		locate     func() (string, error)
		wantStatus string
		wantDetail string
	}{
		{"found", func() (string, error) { return "/usr/local/bin/cloudflared", nil }, "ok", "/usr/local/bin/cloudflared"},
		{"missing", func() (string, error) { return "", errors.New("absent") }, "fail", "install it"},
	}
	for _, online := range []bool{false, true} {
		for _, tc := range tests {
			t.Run(tc.name, func(t *testing.T) {
				box := newCloudflareBox(t)
				box.locate = tc.locate

				got := checkNamed(t, box.doctor(online).Run(context.Background()), checkCloudflared)

				if got.Status != tc.wantStatus || !strings.Contains(got.Detail, tc.wantDetail) {
					t.Errorf("check = %+v, want %s containing %q", got, tc.wantStatus, tc.wantDetail)
				}
			})
		}
	}
}

func TestDoctorReportsTunnelOperationsThatDidNotFinish(t *testing.T) {
	tests := []struct {
		name       string
		setup      func(box *cloudflareBox)
		wantStatus string
		wantIn     []string
	}{
		{"none", func(*cloudflareBox) {}, "ok", nil},
		{"finished operations are not stuck", func(box *cloudflareBox) {
			node := box.addNode("done-1", domain.TransportCloudflare)
			box.startOperation(node, database.TunnelEnable, database.PhaseCommitted)
		}, "ok", nil},
		{"an enable in progress", func(box *cloudflareBox) {
			box.startOperation(box.addNode("web-1", domain.TransportDirect), database.TunnelEnable, database.PhaseTunnelCreated)
		}, "warn", []string{"web-1", "enable", "tunnel_created"}},
		{"a halted disable names the phase it halted at", func(box *cloudflareBox) {
			op := box.startOperation(box.addNode("db-1", domain.TransportCloudflare), database.TunnelDisable, database.PhaseSwitched)
			box.haltOperation(op, database.PhaseConflict)
		}, "warn", []string{"db-1", "disable", "conflict at switched"}},
		{"several nodes", func(box *cloudflareBox) {
			box.startOperation(box.addNode("a-1", domain.TransportDirect), database.TunnelEnable, database.PhaseStarted)
			box.startOperation(box.addNode("b-1", domain.TransportDirect), database.TunnelEnable, database.PhaseDNSCreated)
		}, "warn", []string{"a-1", "b-1", "dns_created"}},
	}
	for _, online := range []bool{false, true} {
		for _, tc := range tests {
			t.Run(tc.name, func(t *testing.T) {
				box := newCloudflareBox(t)
				tc.setup(box)

				got := checkNamed(t, box.doctor(online).Run(context.Background()), checkCFOperations)

				if got.Status != tc.wantStatus {
					t.Errorf("status = %s (%s), want %s", got.Status, got.Detail, tc.wantStatus)
				}
				for _, want := range tc.wantIn {
					if !strings.Contains(got.Detail, want) {
						t.Errorf("detail %q does not contain %q", got.Detail, want)
					}
				}
			})
		}
	}
}

func TestDoctorServiceTokenExpiry(t *testing.T) {
	tests := []struct {
		name       string
		transport  domain.Transport
		state      func(box *cloudflareBox) // nil: no state recorded
		dropSecret bool
		wantStatus string
		wantDetail string
	}{
		{"not created and unused", domain.TransportDirect, nil, false, "ok", "not created yet"},
		{"not created but a node uses the tunnel", domain.TransportCloudflare, nil, false, "fail", "not created yet"},
		{"far from expiry", domain.TransportCloudflare, func(b *cloudflareBox) { b.recordServiceToken(b.clock.Now().Add(90 * 24 * time.Hour)) }, false, "ok", "expires"},
		{"31 days left", domain.TransportCloudflare, func(b *cloudflareBox) { b.recordServiceToken(b.clock.Now().Add(31 * 24 * time.Hour)) }, false, "ok", "expires"},
		{"29 days left", domain.TransportCloudflare, func(b *cloudflareBox) { b.recordServiceToken(b.clock.Now().Add(29 * 24 * time.Hour)) }, false, "warn", "rotate-access-token"},
		{"expired and in use", domain.TransportCloudflare, func(b *cloudflareBox) { b.recordServiceToken(b.clock.Now().Add(-time.Hour)) }, false, "fail", "expired"},
		{"expired and unused", domain.TransportDirect, func(b *cloudflareBox) { b.recordServiceToken(b.clock.Now().Add(-time.Hour)) }, false, "warn", "expired"},
		{"no expiry recorded", domain.TransportCloudflare, func(b *cloudflareBox) { b.recordServiceToken(time.Time{}) }, false, "ok", "no expiry"},
		{"secret lost while in use", domain.TransportCloudflare, func(b *cloudflareBox) { b.recordServiceToken(b.clock.Now().Add(90 * 24 * time.Hour)) }, true, "fail", "secret is not in the store"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			box := newCloudflareBox(t)
			box.addNode("web-1", tc.transport)
			if tc.state != nil {
				tc.state(box)
			}
			if tc.dropSecret {
				delete(box.shelf.vals, "cloudflare/access-service-token")
			}

			got := checkNamed(t, box.doctor(true).Run(context.Background()), checkCFServiceToken)

			if got.Status != tc.wantStatus || !strings.Contains(got.Detail, tc.wantDetail) {
				t.Errorf("check = %+v, want %s containing %q", got, tc.wantStatus, tc.wantDetail)
			}
		})
	}
}

func TestDoctorAPITokenProvesValidityAndReadsAndNeverClaimsEditRights(t *testing.T) {
	tests := []struct {
		name        string
		prepare     func(box *cloudflareBox)
		wantToken   string
		wantReads   string
		readsDetail string
	}{
		{"everything readable", func(*cloudflareBox) {}, "ok", "ok", "can read tunnels, access.apps, access.policies, access.service_tokens, zone, dns"},
		{"a read is forbidden", func(box *cloudflareBox) { box.cf.Inject(cffake.OpPolicyList, cffake.Forbidden, -1) }, "ok", "fail", "cannot read access.policies"},
		{"a token Cloudflare does not accept", func(box *cloudflareBox) { box.shelf.vals["cloudflare/api-token"] = "not-the-token" }, "fail", "fail", "cannot read"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			box := newCloudflareBox(t)
			tc.prepare(box)

			checks := box.doctor(true).Run(context.Background())

			if got := checkNamed(t, checks, checkCFAPIToken); got.Status != tc.wantToken {
				t.Errorf("token check = %+v, want %s", got, tc.wantToken)
			}
			if got := checkNamed(t, checks, checkCFAPIReads); got.Status != tc.wantReads || !strings.Contains(got.Detail, tc.readsDetail) {
				t.Errorf("reads check = %+v, want %s containing %q", got, tc.wantReads, tc.readsDetail)
			}
			edit := checkNamed(t, checks, checkCFEditRights)
			if edit.Status != "warn" || !strings.Contains(edit.Detail, "not verifiable") {
				t.Errorf("edit rights check = %+v, want warn: not verifiable", edit)
			}
			for _, c := range checks {
				if strings.Contains(c.Detail, box.cf.Token()) {
					t.Errorf("check %s leaks the API token: %q", c.Name, c.Detail)
				}
			}
		})
	}
}

func TestDoctorAPITokenRemovedFromTheStoreIsOnlyAWarning(t *testing.T) {
	box := newCloudflareBox(t)
	delete(box.shelf.vals, "cloudflare/api-token")

	checks := box.doctor(true).Run(context.Background())

	if got := checkNamed(t, checks, checkCFAPIToken); got.Status != "warn" || !strings.Contains(got.Detail, "secret://cloudflare/api-token") {
		t.Errorf("token check = %+v, want a warning naming the reference", got)
	}
	for _, c := range checks {
		if c.Name == checkCFAPIReads || c.Name == checkCFEditRights {
			t.Errorf("%s reported without a token to probe with", c.Name)
		}
	}
}

func TestDoctorOfflineNeverCallsCloudflareNorChecksTheServiceToken(t *testing.T) {
	box := newCloudflareBox(t)
	box.addNode("web-1", domain.TransportCloudflare) // would fail the service token check online

	checks := box.doctor(false).Run(context.Background())

	var names []string
	for _, c := range checks {
		names = append(names, c.Name)
	}
	if want := []string{checkCloudflared, checkCFOperations}; strings.Join(names, ",") != strings.Join(want, ",") {
		t.Errorf("offline checks = %v, want %v", names, want)
	}
	if got := len(box.cf.Requests()); got != 0 {
		t.Errorf("%d requests reached Cloudflare offline, want none", got)
	}
}

func TestDoctorShowsNoCloudflareCheckWithoutTheBlock(t *testing.T) {
	box := newDoctorBox(t)
	box.b.cfg = &config.Config{}

	if checks := box.b.cloudflareChecks(context.Background()); len(checks) != 0 {
		t.Errorf("checks = %v, want none without a cloudflare: block", checks)
	}
}

func TestDoctorRevokedAPITokenIsOnlyAWarningOnceEveryTunnelIsProvisioned(t *testing.T) {
	tests := []struct {
		name    string
		prepare func(box *cloudflareBox)
		want    string
	}{
		{"nothing tunnelled yet", func(*cloudflareBox) {}, "fail"},
		{"a node dials through the tunnel", func(box *cloudflareBox) { box.addNode("web-1", domain.TransportCloudflare) }, "warn"},
		{"a tunnel operation is unfinished", func(box *cloudflareBox) {
			box.startOperation(box.addNode("web-1", domain.TransportCloudflare), database.TunnelEnable, database.PhaseStarted)
		}, "fail"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			box := newCloudflareBox(t)
			box.shelf.vals["cloudflare/api-token"] = "revoked-token"
			tc.prepare(box)

			checks := box.doctor(true).Run(context.Background())

			got := checkNamed(t, checks, checkCFAPIToken)
			if got.Status != tc.want {
				t.Fatalf("token check = %+v, want %s", got, tc.want)
			}
			if tc.want == "warn" && !strings.Contains(got.Detail, "provisioning unavailable (not needed for dialling)") {
				t.Errorf("detail = %q, want the provisioning-unavailable wording", got.Detail)
			}
			if reads := checkNamed(t, checks, checkCFAPIReads); reads.Status != tc.want {
				t.Errorf("reads check = %+v, want %s", reads, tc.want)
			}
		})
	}
}

func TestTheCloudflaredCheckSaysWhyAndHowToInstallOnThisSystem(t *testing.T) {
	refused := func() (string, error) {
		return "", smerr.New(smerr.CodeCapabilityUnavailable, "", "/usr/local/bin/cloudflared is writable by group or others")
	}
	c := cloudflaredCheck(refused)
	if c.Status != checkFail || !strings.Contains(c.Detail, "writable by group or others") {
		t.Errorf("check = %+v: it must carry the reason the binary was refused", c)
	}
	if _, err := ssh.LocateCloudflared(); ssh.CloudflaredMissing(err) {
		if got := cloudflaredFailure(err, "linux"); strings.Count(got, "install it") != 1 {
			t.Errorf("detail = %q: the install advice must appear once", got)
		}
	}
	if hint := cloudflaredInstallHint("darwin"); !strings.Contains(hint, "brew install cloudflared") {
		t.Errorf("macOS hint = %q", hint)
	}
	if hint := cloudflaredInstallHint("linux"); !strings.Contains(hint, "pkg.cloudflare.com") {
		t.Errorf("Linux hint = %q", hint)
	}
}
