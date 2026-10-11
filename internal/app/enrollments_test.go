package app

import (
	"context"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/autarquico/supermgmt/internal/api/wire"
	"github.com/autarquico/supermgmt/internal/database"
	"github.com/autarquico/supermgmt/internal/domain"
	smerr "github.com/autarquico/supermgmt/internal/errors"
	"github.com/autarquico/supermgmt/internal/secrets"
)

const instanceKey = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIInstanceKeyForTestsOnly"

var joiner = netip.MustParseAddr("203.0.113.7")

type enrollmentFixture struct {
	*fixture
	svc      *EnrollmentService
	instance domain.ID
	version  int
}

func newEnrollmentFixture(t *testing.T) *enrollmentFixture {
	t.Helper()
	f := newFixture(t)
	e := &enrollmentFixture{fixture: f, instance: f.ids.NewID(), version: 1}
	f.inTx(func(ctx context.Context, tx *database.Tx) error {
		return database.CreateInstance(ctx, tx, database.Instance{ID: e.instance, Name: "sm", CreatedAt: f.clock.Now()})
	})
	identity := func(context.Context) (secrets.Identity, error) {
		return secrets.Identity{
			Ref: secrets.Ref{Name: secrets.SSHIdentityName, Version: e.version}, AuthorizedKey: instanceKey, FingerprintSHA256: "SHA256:instance",
		}, nil
	}
	svc, err := NewEnrollments(f.cfg, &countingMinter{}, identity)
	if err != nil {
		t.Fatalf("NewEnrollments: %v", err)
	}
	e.svc = svc
	return e
}

func (e *enrollmentFixture) issue(r wire.EnrollmentRequest) wire.EnrollmentIssued {
	e.t.Helper()
	issued, err := e.svc.Create(context.Background(), e.caller(e.admin), r)
	if err != nil {
		e.t.Fatalf("Create: %v", err)
	}
	return issued
}

func enrollAs(token, hostname string) wire.EnrollRequest {
	return wire.EnrollRequest{Token: token, HostPublicKey: testHostKey, Hostname: hostname}
}

func (e *enrollmentFixture) enroll(r wire.EnrollRequest) (wire.Enrolled, error) {
	return e.svc.Enroll(context.Background(), joiner, r)
}

func TestCreateIssuesAJoinTokenOnceAndStoresOnlyItsHash(t *testing.T) {
	e := newEnrollmentFixture(t)

	issued := e.issue(wire.EnrollmentRequest{Tags: []string{"edge"}, MaxNodes: 3})

	if !strings.HasPrefix(issued.Token, "smj_") {
		t.Fatalf("token = %q, want a join token", issued.Token)
	}
	stored, err := database.GetJoinToken(context.Background(), e.db.Reader(), issued.ID)
	if err != nil || stored.TokenHash == issued.Token || stored.Constraints.MaxNodes != 3 || stored.CreatedBy != e.admin {
		t.Fatalf("stored = %+v, %v", stored, err)
	}
	if want := e.clock.Now().Add(defaultEnrollmentTTL); !issued.ExpiresAt.Equal(want) {
		t.Errorf("ExpiresAt = %v, want the one-hour default %v", issued.ExpiresAt, want)
	}
}

func TestCreateValidatesConstraints(t *testing.T) {
	e := newEnrollmentFixture(t)
	tests := map[string]wire.EnrollmentRequest{
		"expiry beyond 24h":  {ExpiresAt: e.clock.Now().Add(25 * time.Hour)},
		"expiry in the past": {ExpiresAt: e.clock.Now().Add(-time.Minute)},
		"negative max nodes": {MaxNodes: -1},
		"bad tag":            {Tags: []string{"has space"}},
		"bad cidr":           {SourceCIDRs: []string{"10.0.0.0"}},
	}
	for name, r := range tests {
		t.Run(name, func(t *testing.T) {
			_, err := e.svc.Create(context.Background(), e.caller(e.admin), r)

			wantError(t, err, smerr.CodeInvalidArgument, "")
		})
	}
}

func TestCreateNeedsThePolicyGrantAndRefusesIdempotencyKeys(t *testing.T) {
	e := newEnrollmentFixture(t)

	_, err := e.svc.Create(context.Background(), e.caller(e.dave), wire.EnrollmentRequest{})
	wantError(t, err, smerr.CodePolicyDenied, smerr.ReasonDefaultDeny)

	keyed := e.caller(e.admin)
	keyed.Idempotency = &Idempotency{Key: "k"}
	_, err = e.svc.Create(context.Background(), keyed, wire.EnrollmentRequest{})
	wantError(t, err, smerr.CodeInvalidArgument, "")
	if n := e.count(`SELECT count(*) FROM idempotency_records`); n != 0 {
		t.Fatalf("idempotency_records = %d, want none", n)
	}
}

func TestEnrollCreatesAPinnedManagedNodeAndReturnsTheInstanceKey(t *testing.T) {
	e := newEnrollmentFixture(t)
	issued := e.issue(wire.EnrollmentRequest{Tags: []string{"edge", "web"}})

	got, err := e.enroll(enrollAs(issued.Token, "edge-1"))
	if err != nil {
		t.Fatalf("Enroll: %v", err)
	}
	if got.AuthorizedKey != instanceKey || got.FingerprintSHA256 != "SHA256:instance" || got.KeyVersion != 1 ||
		got.InstanceID != e.instance || got.SSHUser != "supermgmt" {
		t.Fatalf("answer = %+v", got)
	}
	node, err := database.GetNode(context.Background(), e.db.Reader(), got.NodeID)
	if err != nil {
		t.Fatalf("GetNode: %v", err)
	}
	if node.ManagementState != domain.ManagementManaged || node.Name != "edge-1" || node.Endpoint.HostPublicKey != testHostKey ||
		node.Endpoint.Host != "203.0.113.7" || node.Endpoint.Port != 22 || node.Endpoint.User != "supermgmt" ||
		node.CredentialRef != "secret://ssh/default@1" || strings.Join(node.Tags, ",") != "edge,web" {
		t.Fatalf("node = %+v", node)
	}
	digest := database.JoinRequestDigest(testHostKey, "edge-1")
	if node.Metadata[database.JoinMetaRequestDigest] != digest || node.Metadata[database.JoinMetaTokenID] != issued.ID.String() {
		t.Fatalf("metadata = %v, want the token id and request digest", node.Metadata)
	}
}

func TestATokenWithOneSlotEnrollsOneNode(t *testing.T) {
	e := newEnrollmentFixture(t)
	issued := e.issue(wire.EnrollmentRequest{})
	if _, err := e.enroll(enrollAs(issued.Token, "edge-1")); err != nil {
		t.Fatalf("first Enroll: %v", err)
	}

	_, err := e.enroll(wire.EnrollRequest{Token: issued.Token, HostPublicKey: newAuthorizedKey(), Hostname: "edge-2"})

	wantError(t, err, smerr.CodeConflict, "")
	if n := e.count(`SELECT count(*) FROM nodes WHERE json_extract(metadata_json, '$.join_token_id') IS NOT NULL`); n != 1 {
		t.Fatalf("enrolled nodes = %d, want 1", n)
	}
}

func TestALostResponseRetryReturnsTheSameNodeWithoutUsingASlot(t *testing.T) {
	e := newEnrollmentFixture(t)
	issued := e.issue(wire.EnrollmentRequest{MaxNodes: 2})
	first, err := e.enroll(enrollAs(issued.Token, "edge-1"))
	if err != nil {
		t.Fatalf("first Enroll: %v", err)
	}
	e.version = 2 // the instance key rotated before the retry arrived

	again, err := e.enroll(enrollAs(issued.Token, "edge-1"))

	if err != nil || again != first {
		t.Fatalf("retry = %+v, %v; want %+v", again, err, first)
	}
	token, _ := database.GetJoinToken(context.Background(), e.db.Reader(), issued.ID)
	if token.Uses != 1 {
		t.Fatalf("uses = %d, want the retry to use no slot", token.Uses)
	}
}

func TestADifferentDigestOnAnExhaustedTokenIsAConflict(t *testing.T) {
	e := newEnrollmentFixture(t)
	issued := e.issue(wire.EnrollmentRequest{})
	if _, err := e.enroll(enrollAs(issued.Token, "edge-1")); err != nil {
		t.Fatalf("first Enroll: %v", err)
	}

	for name, r := range map[string]wire.EnrollRequest{
		"other host key": {Token: issued.Token, HostPublicKey: newAuthorizedKey(), Hostname: "edge-1"},
		"other hostname": enrollAs(issued.Token, "edge-9"),
	} {
		t.Run(name, func(t *testing.T) {
			_, err := e.enroll(r)

			wantError(t, err, smerr.CodeConflict, "")
		})
	}
}

func TestConcurrentConsumptionNeverExceedsMaxNodes(t *testing.T) {
	e := newEnrollmentFixture(t)
	issued := e.issue(wire.EnrollmentRequest{MaxNodes: 2})
	const attempts = 8
	var (
		wg      sync.WaitGroup
		mu      sync.Mutex
		success int
		refused int
	)
	for i := range attempts {
		wg.Add(1)
		go func() {
			defer wg.Done()
			r := wire.EnrollRequest{Token: issued.Token, HostPublicKey: newAuthorizedKey(), Hostname: "edge-" + string(rune('a'+i))}
			_, err := e.enroll(r)
			mu.Lock()
			defer mu.Unlock()
			switch {
			case err == nil:
				success++
			case smerr.CodeOf(err) == smerr.CodeConflict:
				refused++
			default:
				t.Errorf("Enroll: %v", err)
			}
		}()
	}
	wg.Wait()

	if success != 2 || refused != attempts-2 {
		t.Fatalf("success = %d, refused = %d; want 2 and %d", success, refused, attempts-2)
	}
}

func TestConcurrentRetriesOfOneRequestShareOneNode(t *testing.T) {
	e := newEnrollmentFixture(t)
	issued := e.issue(wire.EnrollmentRequest{})
	const attempts = 6
	nodes := make(chan domain.ID, attempts)
	var wg sync.WaitGroup
	for range attempts {
		wg.Add(1)
		go func() {
			defer wg.Done()
			got, err := e.enroll(enrollAs(issued.Token, "edge-1"))
			if err != nil {
				t.Errorf("Enroll: %v", err)
			}
			nodes <- got.NodeID
		}()
	}
	wg.Wait()
	close(nodes)

	seen := map[domain.ID]bool{}
	for id := range nodes {
		seen[id] = true
	}
	if len(seen) != 1 {
		t.Fatalf("retries produced %d nodes, want 1", len(seen))
	}
}

func TestSourceCIDRsRestrictWhereATokenWorks(t *testing.T) {
	e := newEnrollmentFixture(t)
	issued := e.issue(wire.EnrollmentRequest{SourceCIDRs: []string{"198.51.100.0/24"}})

	_, err := e.enroll(enrollAs(issued.Token, "edge-1"))
	wantError(t, err, smerr.CodePolicyDenied, smerr.ReasonDefaultDeny)
	if n := e.count(`SELECT count(*) FROM events WHERE action = 'enrollment.denied'`); n != 1 {
		t.Errorf("enrollment.denied events = %d, want 1", n)
	}

	_, err = e.svc.Enroll(context.Background(), netip.MustParseAddr("198.51.100.20"), enrollAs(issued.Token, "edge-1"))
	if err != nil {
		t.Fatalf("Enroll from inside the CIDR: %v", err)
	}
}

func TestExpiredAndForeignTokensAreRefused(t *testing.T) {
	e := newEnrollmentFixture(t)
	issued := e.issue(wire.EnrollmentRequest{})
	if _, err := e.enroll(enrollAs(issued.Token, "edge-1")); err != nil {
		t.Fatalf("Enroll: %v", err)
	}
	e.clock.Advance(2 * time.Hour)

	_, retry := e.enroll(enrollAs(issued.Token, "edge-1"))
	wantError(t, retry, smerr.CodeConflict, "")

	_, unknown := e.enroll(enrollAs("smj_999", "edge-1"))
	wantError(t, unknown, smerr.CodeUnauthenticated, "")
	_, wrongKind := e.enroll(enrollAs("smt_1", "edge-1"))
	wantError(t, wrongKind, smerr.CodeUnauthenticated, "")
}

func TestEnrollRejectsMalformedRequestsWithoutCostingASlot(t *testing.T) {
	e := newEnrollmentFixture(t)
	issued := e.issue(wire.EnrollmentRequest{MaxNodes: 5})
	tests := map[string]wire.EnrollRequest{
		"no host key":       {Token: issued.Token, Hostname: "edge-1"},
		"junk host key":     {Token: issued.Token, HostPublicKey: "nope", Hostname: "edge-1"},
		"bad hostname":      {Token: issued.Token, HostPublicKey: testHostKey, Hostname: "-bad host"},
		"port out of range": {Token: issued.Token, HostPublicKey: testHostKey, Hostname: "edge-1", SSHPort: 70000},
	}
	for name, r := range tests {
		t.Run(name, func(t *testing.T) {
			_, err := e.enroll(r)

			wantError(t, err, smerr.CodeInvalidArgument, "")
		})
	}
	if token, _ := database.GetJoinToken(context.Background(), e.db.Reader(), issued.ID); token.Uses != 0 {
		t.Fatalf("uses = %d, want invalid requests to cost no slot", token.Uses)
	}
}

func TestAnEnrolledNodeIsNeverChangedByAnotherRequest(t *testing.T) {
	e := newEnrollmentFixture(t)
	first := e.issue(wire.EnrollmentRequest{Tags: []string{"old"}})
	node, err := e.enroll(enrollAs(first.Token, "edge-1"))
	if err != nil {
		t.Fatalf("first Enroll: %v", err)
	}
	fresh := e.issue(wire.EnrollmentRequest{Tags: []string{"new"}})
	spent := e.issue(wire.EnrollmentRequest{Tags: []string{"spent"}})
	otherKey := newAuthorizedKey()
	if _, err := e.enroll(wire.EnrollRequest{Token: spent.Token, HostPublicKey: otherKey, Hostname: "edge-2"}); err != nil {
		t.Fatalf("enroll with the token to be spent: %v", err)
	}

	for name, token := range map[string]string{"fresh token": fresh.Token, "exhausted token": spent.Token} {
		t.Run(name, func(t *testing.T) {
			_, err := e.enroll(enrollAs(token, "edge-1"))

			wantError(t, err, smerr.CodeConflict, "")
			stored, _ := database.GetNode(context.Background(), e.db.Reader(), node.NodeID)
			if strings.Join(stored.Tags, ",") != "old" {
				t.Fatalf("tags = %v, want unchanged [old]", stored.Tags)
			}
			if got, _ := database.GetJoinToken(context.Background(), e.db.Reader(), fresh.ID); got.Uses != 0 {
				t.Fatalf("fresh token uses = %d, want none", got.Uses)
			}
			if n := e.count(`SELECT count(*) FROM events WHERE action = 'enrollment.denied'`); n == 0 {
				t.Fatal("refusal was not audited")
			}
		})
	}
}

func TestTheExactReplayOnAnExhaustedTokenStillReturnsItsNode(t *testing.T) {
	e := newEnrollmentFixture(t)
	issued := e.issue(wire.EnrollmentRequest{})
	first, err := e.enroll(enrollAs(issued.Token, "edge-1"))
	if err != nil {
		t.Fatalf("first Enroll: %v", err)
	}

	again, err := e.enroll(enrollAs(issued.Token, "edge-1"))

	if err != nil || again != first {
		t.Fatalf("replay = %+v, %v; want %+v", again, err, first)
	}
}

func TestATakenNameGetsTheDigestAsSuffix(t *testing.T) {
	e := newEnrollmentFixture(t)
	issued := e.issue(wire.EnrollmentRequest{MaxNodes: 2})
	first, _ := e.enroll(enrollAs(issued.Token, "edge-1"))

	second, err := e.enroll(wire.EnrollRequest{Token: issued.Token, HostPublicKey: newAuthorizedKey(), Hostname: "edge-1"})

	if err != nil || second.NodeID == first.NodeID {
		t.Fatalf("second = %+v, %v", second, err)
	}
	node, _ := database.GetNode(context.Background(), e.db.Reader(), second.NodeID)
	if !strings.HasPrefix(node.Name, "edge-1-") {
		t.Fatalf("name = %q, want edge-1-<digest>", node.Name)
	}
}

func TestEnrollmentNeverStoresAnIdempotencyRecord(t *testing.T) {
	e := newEnrollmentFixture(t)
	issued := e.issue(wire.EnrollmentRequest{})
	if _, err := e.enroll(enrollAs(issued.Token, "edge-1")); err != nil {
		t.Fatalf("Enroll: %v", err)
	}

	if n := e.count(`SELECT count(*) FROM idempotency_records`); n != 0 {
		t.Fatalf("idempotency_records = %d, want none", n)
	}
}
