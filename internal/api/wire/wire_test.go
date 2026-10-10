package wire

import (
	"encoding/json"
	"errors"
	"net/url"
	"reflect"
	"strings"
	"testing"

	"github.com/autarquico/supermgmt/internal/domain"
	smerr "github.com/autarquico/supermgmt/internal/errors"
)

func TestEnvelopesHaveTheSpecShape(t *testing.T) {
	ok, err := json.Marshal(Envelope[Health]{Data: Health{Status: "ok"}})
	if err != nil {
		t.Fatal(err)
	}
	if string(ok) != `{"data":{"status":"ok"},"meta":{}}` {
		t.Errorf("success envelope = %s", ok)
	}
	failure, err := json.Marshal(ErrorEnvelope{Error: Error{
		Code: smerr.CodePolicyDenied, Message: "action requires approval", CorrelationID: "c1",
		Details: map[string]any{DetailReason: string(smerr.ReasonDefaultDeny)},
	}})
	if err != nil {
		t.Fatal(err)
	}
	want := `{"error":{"code":"POLICY_DENIED","message":"action requires approval","correlation_id":"c1","details":{"reason":"DEFAULT_DENY"}}}`
	if string(failure) != want {
		t.Errorf("error envelope = %s\nwant %s", failure, want)
	}
}

func TestErrorBodyBecomesTheTypedError(t *testing.T) {
	var env ErrorEnvelope
	body := `{"error":{"code":"CONFLICT","message":"stale","correlation_id":"c","details":{"reason":"PLAN_STALE"}}}`
	if err := json.Unmarshal([]byte(body), &env); err != nil {
		t.Fatal(err)
	}
	err := env.Error.Err()
	if !errors.Is(err, smerr.New(smerr.CodeConflict, smerr.ReasonPlanStale, "")) {
		t.Errorf("Err() = %v, want CONFLICT/PLAN_STALE", err)
	}
	if (Error{Code: smerr.CodeInternal}).Reason() != "" {
		t.Error("an error without details has no reason")
	}
}

func TestDirectHasExactlyTheTwoSlots(t *testing.T) {
	got, err := json.Marshal(Direct[Node]{})
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != `{"applied":null,"pending":null}` {
		t.Errorf("Direct = %s", got)
	}
}

func TestPathFillsPlaceholdersInOrder(t *testing.T) {
	tests := []struct {
		pattern string
		values  []string
		want    string
	}{
		{PathNode, []string{"n1"}, "/api/v1/nodes/n1"},
		{PathNodeSessionEnd, []string{"n1", "s1"}, "/api/v1/nodes/n1/sessions/s1/end"},
		{PathNode, []string{"../jobs"}, "/api/v1/nodes/..%2Fjobs"},
		{PathNode, []string{"a b?c"}, "/api/v1/nodes/a%20b%3Fc"},
		{PathNodeSessionEnd, []string{"n1"}, "/api/v1/nodes/n1/sessions/{sid}/end"},
		{PathNodes, []string{"ignored"}, "/api/v1/nodes"},
	}
	for _, tt := range tests {
		if got := Path(tt.pattern, tt.values...); got != tt.want {
			t.Errorf("Path(%s, %v) = %s, want %s", tt.pattern, tt.values, got, tt.want)
		}
	}
}

func TestEveryPathIsUnderThePrefixOrHealth(t *testing.T) {
	for _, p := range []string{
		PathMe, PathPresence, PathSSHKey, PathNodes, PathServiceRestart, PathEvents, PathJobResolve,
		PathEventStream, PathOIDCStart, PathOIDCExchange, PathOIDCDevice, PathOIDCDevicePoll, PathBootstrap,
		PathLogout, PathTokens, PathToken, PathSecrets, PathMasterKeyRotate, PathMasterKeyRetire,
		PathMasterKeyExport, PathSSHKeyRotate, PathBackups, PathEnrollments, PathEnroll,
	} {
		if !strings.HasPrefix(p, Prefix+"/") {
			t.Errorf("%s is outside %s", p, Prefix)
		}
	}
}

func TestAdminSocketServesExactlyFourRoutesOutsideTheAPI(t *testing.T) {
	admin := []string{AdminPathBootstrapCode, AdminPathGrant, AdminPathRestoreComplete, AdminPathDoctor}
	seen := map[string]bool{}
	for _, p := range admin {
		if strings.HasPrefix(p, Prefix) || !strings.HasPrefix(p, "/admin/") || seen[p] {
			t.Errorf("admin path %s must be unique, under /admin/ and outside %s", p, Prefix)
		}
		seen[p] = true
	}
}

func TestIssuedCredentialsSerializeTheirValue(t *testing.T) {
	// A credential-issuing response must carry the plaintext exactly once, in
	// "token" (or "code"); a redacting type here would make the token unusable.
	b, err := json.Marshal(TokenIssued{Value: "smt_x"})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), `"token":"smt_x"`) {
		t.Errorf("TokenIssued = %s", b)
	}
}

func TestQueriesRoundTrip(t *testing.T) {
	id := domain.ID("0190a5e2-7c41-7b9e-9f0e-3d2c1b0a9f88")
	nodes := NodeQuery{PageQuery: PageQuery{Cursor: "abc", Limit: 20}, Environment: "prod", Tag: "docker", Reachability: domain.ReachabilityUnreachable}
	if got, err := ParseNodeQuery(nodes.Values()); err != nil || !reflect.DeepEqual(got, nodes) {
		t.Errorf("nodes: got %+v, %v", got, err)
	}
	jobs := JobQuery{States: []domain.JobState{domain.JobAwaitingApproval, domain.JobInterrupted}}
	if got, err := ParseJobQuery(jobs.Values()); err != nil || !reflect.DeepEqual(got, jobs) {
		t.Errorf("jobs: got %+v, %v", got, err)
	}
	events := EventQuery{ResourceType: domain.ResourceJob, ResourceID: id, AfterSeq: 42}
	if got, err := ParseEventQuery(events.Values()); err != nil || !reflect.DeepEqual(got, events) {
		t.Errorf("events: got %+v, %v", got, err)
	}
	logs := LogQuery{Lines: 500}
	if got, err := ParseLogQuery(logs.Values()); err != nil || got != logs {
		t.Errorf("logs: got %+v, %v", got, err)
	}
	if len((NodeQuery{}).Values()) != 0 {
		t.Error("a zero query must encode no parameters")
	}
}

func TestQueriesRejectInvalidValues(t *testing.T) {
	parsers := map[string]func(url.Values) error{
		"limit too large":    func(v url.Values) error { _, err := ParsePageQuery(v); return err },
		"bad reachability":   func(v url.Values) error { _, err := ParseNodeQuery(v); return err },
		"bad state":          func(v url.Values) error { _, err := ParseJobQuery(v); return err },
		"bad resource id":    func(v url.Values) error { _, err := ParseEventQuery(v); return err },
		"too many log lines": func(v url.Values) error { _, err := ParseLogQuery(v); return err },
	}
	inputs := map[string]url.Values{
		"limit too large":    {QueryLimit: {"501"}},
		"bad reachability":   {QueryReachability: {"maybe"}},
		"bad state":          {QueryState: {"queued", "paused"}},
		"bad resource id":    {QueryResourceID: {"42"}},
		"too many log lines": {QueryLines: {"10001"}},
	}
	for name, parse := range parsers {
		if err := parse(inputs[name]); smerr.CodeOf(err) != smerr.CodeInvalidArgument {
			t.Errorf("%s: got %v, want INVALID_ARGUMENT", name, err)
		}
	}
}
