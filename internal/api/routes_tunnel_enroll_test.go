package api

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	xssh "golang.org/x/crypto/ssh"

	"github.com/autarquico/supermgmt/internal/api/wire"
	"github.com/autarquico/supermgmt/internal/audit"
	"github.com/autarquico/supermgmt/internal/database"
	"github.com/autarquico/supermgmt/internal/domain"
	smerr "github.com/autarquico/supermgmt/internal/errors"
	"github.com/autarquico/supermgmt/internal/secrets"
)

type memorySecrets struct {
	mu     sync.Mutex
	values map[string]audit.Secret
}

func (m *memorySecrets) Get(_ context.Context, ref secrets.Ref) (audit.Secret, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	v, ok := m.values[ref.Name]
	if !ok {
		return "", smerr.New(smerr.CodeNotFound, "", "no such secret")
	}
	return v, nil
}

func (m *memorySecrets) Put(_ context.Context, name string, plaintext audit.Secret, _ map[string]any) (secrets.Ref, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.values[name] = plaintext
	return secrets.Ref{Name: name, Version: 1}, nil
}

const connectorToken = "eyJhIjoiY29ubmVjdG9yLXRva2VuLWZvci10ZXN0cy0wMDAwMDAwMDAwMDAifQ"

func hostKey(t *testing.T) string {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	must(t, err)
	key, err := xssh.NewPublicKey(pub)
	must(t, err)
	return strings.TrimSpace(string(xssh.MarshalAuthorizedKey(key)))
}

// seedEnrollment writes an enrollment of the name waiting in phase, the way the jobs leave it, with the
// connector token in the secret store.
func (h *harness) seedEnrollment(name, phase, scanned string) database.TunnelEnrollment {
	h.t.Helper()
	ctx := context.Background()
	h.ensureInstance()
	now := domain.SystemClock{}.Now().UTC().Truncate(time.Millisecond)
	id := h.ids.NewID()
	var row database.TunnelEnrollment
	must(h.t, h.db.WithWriteTx(ctx, func(ctx context.Context, tx *database.Tx) error {
		instance, err := database.GetInstance(ctx, tx)
		if err != nil {
			return err
		}
		row, err = database.CreateTunnelEnrollment(ctx, tx, database.TunnelEnrollment{
			ID: id, Name: name, AccountID: "acct", Zone: "example.com", InstanceID: instance.ID.String(),
			Hostname: "ssh-" + name + ".example.com", ExpiresAt: now.Add(time.Hour), CreatedAt: now,
			Identity: database.EnrollmentIdentity{PublicKey: "ssh-ed25519 AAAA", Fingerprint: "SHA256:x", CredentialRef: "secret://ssh/default?version=1"},
			TokenRef: "secret://cloudflare/enroll/" + id.String(),
		})
		if err != nil {
			return err
		}
		_, err = tx.ExecContext(ctx, `UPDATE tunnel_enrollments SET phase = ?, scanned_host_key = ? WHERE id = ?`, phase, scanned, id)
		return err
	}))
	h.tunnelSecrets.values["cloudflare/enroll/"+id.String()] = connectorToken
	return row
}

// ensureInstance gives the database the instance row the join line names.
func (h *harness) ensureInstance() {
	h.t.Helper()
	err := h.db.WithWriteTx(context.Background(), func(ctx context.Context, tx *database.Tx) error {
		if _, err := database.GetInstance(ctx, tx); err == nil {
			return nil
		}
		return database.CreateInstance(ctx, tx, database.Instance{ID: h.ids.NewID(), Name: "test", CreatedAt: domain.SystemClock{}.Now()})
	})
	must(h.t, err)
}

func dataOf[T any](t *testing.T, r reply) T {
	t.Helper()
	var env struct {
		Data T `json:"data"`
	}
	if err := json.Unmarshal(r.Body, &env); err != nil {
		t.Fatalf("not an envelope: %s", r.Body)
	}
	return env.Data
}

func enrollmentPath(pattern, name string) string { return wire.Path(pattern, name) }

func TestOnlyTheTokenEndpointCarriesTheConnectorToken(t *testing.T) {
	h := newHarness(t)
	h.seedEnrollment("vps1", "dns_created", "")

	for _, path := range []string{wire.PathTunnelEnrollments, enrollmentPath(wire.PathTunnelEnrollment, "vps1"), wire.PathJobs, wire.PathEvents} {
		r := h.do(http.MethodGet, path, "", nil)
		if r.Status != http.StatusOK || strings.Contains(string(r.Body), connectorToken) {
			t.Errorf("GET %s: status %d, token in body: %v", path, r.Status, strings.Contains(string(r.Body), connectorToken))
		}
	}
	r := h.do(http.MethodGet, enrollmentPath(wire.PathTunnelEnrollmentToken, "vps1"), "", nil)
	if r.Status != http.StatusOK || dataOf[wire.TunnelEnrollmentToken](t, r).Token != connectorToken {
		t.Fatalf("token endpoint: %d %s", r.Status, r.Body)
	}
	if got := r.Header.Get("Cache-Control"); got != "no-store" {
		t.Errorf("Cache-Control = %q", got)
	}
	events := h.do(http.MethodGet, wire.PathEvents, "", nil)
	if strings.Contains(string(events.Body), connectorToken) || !strings.Contains(string(events.Body), "enrollment_token_shown") {
		t.Errorf("the read must be audited without the token: %s", events.Body)
	}
}

func TestTheTokenRouteRefusesAnIdempotencyKeyAndAnEnrollmentThatIsNotWaiting(t *testing.T) {
	h := newHarness(t)
	h.seedEnrollment("vps1", "dns_created", "")
	r := h.do(http.MethodGet, enrollmentPath(wire.PathTunnelEnrollmentToken, "vps1"), "", map[string]string{wire.HeaderIdempotencyKey: "k"})
	if r.Status != http.StatusBadRequest {
		t.Errorf("with a key: %d %s", r.Status, r.Body)
	}
	h.seedEnrollment("vps2", "removing", "")
	r = h.do(http.MethodGet, enrollmentPath(wire.PathTunnelEnrollmentToken, "vps2"), "", nil)
	if r.Status != http.StatusConflict || strings.Contains(string(r.Body), connectorToken) {
		t.Errorf("not waiting: %d %s", r.Status, r.Body)
	}
	r = h.do(http.MethodGet, enrollmentPath(wire.PathTunnelEnrollmentToken, "nobody"), "", nil)
	if r.Status != http.StatusNotFound {
		t.Errorf("unknown name: %d %s", r.Status, r.Body)
	}
}

func TestConfirmingTheScannedKeyMovesTheEnrollmentAndAnotherKeyEndsIt(t *testing.T) {
	h := newHarness(t)
	scanned, other := hostKey(t), hostKey(t)
	h.seedEnrollment("vps1", "scanned", scanned)
	h.seedEnrollment("vps2", "scanned", scanned)
	body := func(k string) string {
		b, _ := json.Marshal(wire.ConfirmTunnelEnrollmentRequest{HostPublicKey: k})
		return string(b)
	}

	r := h.post(enrollmentPath(wire.PathTunnelEnrollmentConfirm, "vps1"), body(scanned), "c1")
	if got := dataOf[wire.TunnelEnrollment](t, r); r.Status != http.StatusOK || got.Phase != "confirmed" {
		t.Fatalf("confirm: %d %s", r.Status, r.Body)
	}
	if r = h.post(enrollmentPath(wire.PathTunnelEnrollmentConfirm, "vps1"), body(scanned), "c2"); r.Status != http.StatusOK {
		t.Errorf("a repeat of the same confirmation: %d %s", r.Status, r.Body)
	}

	r = h.post(enrollmentPath(wire.PathTunnelEnrollmentConfirm, "vps2"), body(other), "c3")
	if e := decodeError(t, r); e.Code != "SSH_HOST_KEY_MISMATCH" {
		t.Fatalf("another key: %d %s", r.Status, r.Body)
	}
	if got := dataOf[wire.TunnelEnrollment](t, h.do(http.MethodGet, enrollmentPath(wire.PathTunnelEnrollment, "vps2"), "", nil)); got.Phase != "mismatch" {
		t.Errorf("phase after a different key = %q", got.Phase)
	}
}

func TestConfirmingACancelledOrUnscannedEnrollmentIsAConflict(t *testing.T) {
	h := newHarness(t)
	scanned := hostKey(t)
	h.seedEnrollment("waiting", "dns_created", "")
	h.seedEnrollment("raced", "scanned", scanned)
	body := `{"host_public_key":"` + scanned + `"}`

	if r := h.post(enrollmentPath(wire.PathTunnelEnrollmentConfirm, "waiting"), body, "k1"); r.Status != http.StatusConflict {
		t.Errorf("not scanned yet: %d %s", r.Status, r.Body)
	}
	if r := h.post(enrollmentPath(wire.PathTunnelEnrollmentCancel, "raced"), "", "k2"); r.Status != http.StatusOK {
		t.Fatalf("cancel: %d %s", r.Status, r.Body)
	}
	if r := h.post(enrollmentPath(wire.PathTunnelEnrollmentConfirm, "raced"), body, "k3"); r.Status != http.StatusConflict {
		t.Errorf("confirm after cancel: %d %s", r.Status, r.Body)
	}
}

func TestRefusingTheScannedKeyIsAHostKeyMismatch(t *testing.T) {
	h := newHarness(t)
	h.seedEnrollment("vps1", "scanned", hostKey(t))
	r := h.post(enrollmentPath(wire.PathTunnelEnrollmentRefuse, "vps1"), "", "k")
	if e := decodeError(t, r); e.Code != "SSH_HOST_KEY_MISMATCH" {
		t.Errorf("refuse: %d %s", r.Status, r.Body)
	}
}

func TestStartingAnEnrollmentAnswersItsViewWithTheJoinLine(t *testing.T) {
	h := newHarness(t)
	h.ensureInstance()
	r := h.post(wire.PathTunnelEnrollments, `{"name":"vps1","tags":["edge"],"expires_in":"90m"}`, "s1")
	if r.Status != http.StatusCreated {
		t.Fatalf("start: %d %s", r.Status, r.Body)
	}
	got := dataOf[wire.Direct[wire.TunnelEnrollment]](t, r).Applied
	if got == nil || got.Name != "vps1" || got.Hostname != "ssh-vps1.example.com" || !strings.Contains(got.JoinLine, "--tunnel --instance ") {
		t.Fatalf("view: %s", r.Body)
	}
	want := domain.SystemClock{}.Now().Add(90 * time.Minute)
	if got.ExpiresAt.Before(want.Add(-time.Minute)) || got.ExpiresAt.After(want.Add(time.Minute)) {
		t.Errorf("expires_at = %s", got.ExpiresAt)
	}
	if again := h.post(wire.PathTunnelEnrollments, `{"name":"vps1","tags":["edge"],"expires_in":"90m"}`, "s1"); string(again.Body) != string(r.Body) {
		t.Errorf("a replay with the same key must answer the same bytes")
	}
	list := dataOf[wire.Page[wire.TunnelEnrollment]](t, h.do(http.MethodGet, wire.PathTunnelEnrollments, "", nil))
	if len(list.Items) != 1 || list.Items[0].Name != "vps1" {
		t.Errorf("list = %+v", list.Items)
	}
}

func TestStartRefusesWhatCannotBeEnrolled(t *testing.T) {
	h := newHarness(t)
	h.seedEnrollment("taken", "dns_created", "")
	for name, tc := range map[string]struct{ body string }{
		"name of an open enrollment": {`{"name":"taken"}`},
		"bad duration":               {`{"name":"vps1","expires_in":"soon"}`},
		"over 24 hours":              {`{"name":"vps1","expires_in":"25h"}`},
		"unknown field":              {`{"name":"vps1","host":"10.0.0.1"}`},
		"no name":                    {`{}`},
	} {
		if r := h.post(wire.PathTunnelEnrollments, tc.body, "k-"+strings.ReplaceAll(name, " ", "-")); r.Status < 400 || r.Status >= 500 {
			t.Errorf("%s: status %d %s", name, r.Status, r.Body)
		}
	}
	if r := h.post(wire.PathTunnelEnrollments, `{"name":"vps1"}`, ""); r.Status != http.StatusBadRequest {
		t.Errorf("no Idempotency-Key: %d", r.Status)
	}
}

func TestTunnelEnrollmentRoutesAreDeniedToACallerWithoutNodeAdd(t *testing.T) {
	h := newHarness(t, func(o *harnessOptions) { o.roles = nil })
	h.ensureInstance()
	h.seedEnrollment("vps1", "dns_created", "")
	for _, path := range []string{enrollmentPath(wire.PathTunnelEnrollmentToken, "vps1")} {
		r := h.do(http.MethodGet, path, "", nil)
		if r.Status != http.StatusForbidden || strings.Contains(string(r.Body), connectorToken) {
			t.Errorf("GET %s: %d %s", path, r.Status, r.Body)
		}
	}
	if r := h.post(wire.PathTunnelEnrollments, `{"name":"vps2"}`, "k"); r.Status != http.StatusForbidden {
		t.Errorf("start: %d %s", r.Status, r.Body)
	}
}
