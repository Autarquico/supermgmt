package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/spf13/cobra"

	"github.com/autarquico/supermgmt/internal/api/wire"
	"github.com/autarquico/supermgmt/internal/client"
	"github.com/autarquico/supermgmt/internal/domain"
	smerr "github.com/autarquico/supermgmt/internal/errors"
)

const (
	mcpMeID     domain.ID = "0192a000-0000-7000-8000-00000000a001"
	mcpOtherID  domain.ID = "0192a000-0000-7000-8000-00000000a002"
	mcpClientID domain.ID = "0192a000-0000-7000-8000-00000000c001"
	mcpJobID    domain.ID = "0192a000-0000-7000-8000-00000000b001"
	mcpSecret             = "smm_AbCdEfGhIjKlMnOp"
)

var mcpNow = time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)

func mcpClientRow(state wire.MCPClientState, requestedBy domain.ID) wire.MCPClient {
	row := wire.MCPClient{
		ID: mcpClientID, IdentityID: "0192a000-0000-7000-8000-00000000d001", Name: "desk",
		Origin: wire.MCPOriginLocal, State: state, RequestedBy: requestedBy,
		ApprovedAt: mcpNow, CreatedAt: mcpNow,
	}
	if state == wire.MCPClientActive {
		issued, expires := mcpNow.Add(time.Hour), mcpNow.Add(90*24*time.Hour)
		row.TokenIssuedAt, row.TokenExpiresAt = &issued, &expires
	}
	return row
}

// mcpDaemon is a fake daemon holding the MCP clients under test.
type mcpDaemon struct {
	clients   []wire.MCPClient
	register  func() wire.Direct[wire.MCPClient]
	issueErr  func(w http.ResponseWriter)
	issueSeen int
	api       *fakeAPI
}

func newMCPDaemon(t *testing.T, clients ...wire.MCPClient) *mcpDaemon {
	t.Helper()
	d := &mcpDaemon{clients: clients}
	routes := map[string]http.HandlerFunc{
		"GET " + wire.PathMe: func(w http.ResponseWriter, _ *http.Request) {
			reply(w, 200, wire.Me{IdentityID: mcpMeID, DisplayName: "alex", InstanceMode: "local"})
		},
		"GET " + wire.PathMCPClients: func(w http.ResponseWriter, _ *http.Request) {
			reply(w, 200, wire.Page[wire.MCPClient]{Items: d.clients})
		},
		"POST " + wire.PathMCPClients: func(w http.ResponseWriter, _ *http.Request) {
			reply(w, 202, d.register())
		},
		"POST " + wire.Path(wire.PathMCPClientToken, string(mcpClientID)): func(w http.ResponseWriter, _ *http.Request) {
			d.issueSeen++
			if d.issueErr != nil {
				d.issueErr(w)
				return
			}
			active := mcpClientRow(wire.MCPClientActive, mcpMeID)
			reply(w, 200, wire.MCPTokenIssued{Client: active, Token: mcpSecret})
		},
		"DELETE " + wire.Path(wire.PathMCPClient, string(mcpClientID)): func(w http.ResponseWriter, _ *http.Request) {
			deleted := mcpClientRow(wire.MCPClientDeleted, mcpMeID)
			reply(w, 200, wire.Direct[wire.MCPClient]{Applied: &deleted})
		},
	}
	d.api = newFakeAPI(t, router(routes))
	return d
}

func (d *mcpDaemon) issueCalls() int { return d.issueSeen }

func (d *mcpDaemon) run(deps mcpClientsDeps, args ...string) result {
	root := &cobra.Command{Use: "sm", SilenceUsage: true, SilenceErrors: true, Args: noArgs}
	root.SetFlagErrorFunc(func(_ *cobra.Command, err error) error { return usageErrorf("%s", err) })
	root.PersistentFlags().String("config", "", "")
	root.PersistentFlags().Bool("json", false, "")
	root.PersistentFlags().String("log-level", "info", "")
	mcp := &cobra.Command{Use: "mcp", Args: noArgs}
	mcp.AddCommand(newMCPClientsCmdWith(d.api.Env, deps))
	root.AddCommand(mcp)

	var out, errOut bytes.Buffer
	root.SetOut(&out)
	root.SetErr(&errOut)
	root.SetArgs(append(append([]string{}, d.api.Args...), args...))
	err := root.ExecuteContext(context.Background())
	if err != nil {
		asJSON, _ := root.PersistentFlags().GetBool("json")
		reportError(&errOut, err, asJSON)
	}
	return result{exitCode(err), out.String(), errOut.String()}
}

func realMCPDeps(store client.CredentialStore) mcpClientsDeps {
	deps := defaultMCPClientsDeps(nil)
	deps.openNativeStore = func() (client.CredentialStore, bool) { return store, store != nil }
	return deps
}

func TestMCPClientsListGolden(t *testing.T) {
	remote := wire.MCPClient{
		ID: "0192a000-0000-7000-8000-00000000c002", Name: "claude-web", Origin: wire.MCPOriginRemote,
		State: wire.MCPClientActive, Subject: "alex", ClientID: "web", RequestedBy: mcpMeID,
	}
	d := newMCPDaemon(t,
		mcpClientRow(wire.MCPClientActive, mcpMeID),
		wire.MCPClient{ID: "0192a000-0000-7000-8000-00000000c003", Name: "laptop", Origin: wire.MCPOriginLocal, State: wire.MCPClientPendingToken, RequestedBy: mcpMeID},
		remote,
	)
	r := d.run(realMCPDeps(nil), "mcp", "clients", "list")
	if r.code != 0 || r.stderr != "" {
		t.Fatalf("code=%d stderr=%q", r.code, r.stderr)
	}
	assertGolden(t, "mcp_clients_list.golden", r.stdout)
}

func TestMCPClientsListNeverCarriesATokenInJSON(t *testing.T) {
	d := newMCPDaemon(t, mcpClientRow(wire.MCPClientActive, mcpMeID))
	r := d.run(realMCPDeps(nil), "--json", "mcp", "clients", "list")
	if r.code != 0 || strings.Contains(r.stdout, "token\"") && strings.Contains(r.stdout, mcpSecret) {
		t.Fatalf("code=%d out=%s", r.code, r.stdout)
	}
	var page wire.Page[wire.MCPClient]
	if err := json.Unmarshal([]byte(r.stdout), &page); err != nil || len(page.Items) != 1 {
		t.Fatalf("not a client page: %v %s", err, r.stdout)
	}
}

func TestMCPClientsAddRegistrationPending(t *testing.T) {
	d := newMCPDaemon(t)
	d.register = func() wire.Direct[wire.MCPClient] {
		return wire.Direct[wire.MCPClient]{Pending: &wire.Submission{
			Job:    wire.Job{ID: mcpJobID, Type: "control_plane.apply", State: "waiting_approval"},
			Policy: wire.Policy{ApprovalRequired: true, Quorum: 1},
		}}
	}
	dest := filepath.Join(t.TempDir(), "token")
	r := d.run(realMCPDeps(nil), "mcp", "clients", "add", "desk", "--token-file", dest)
	if r.code != 0 {
		t.Fatalf("code=%d stderr=%q", r.code, r.stderr)
	}
	for _, want := range []string{string(mcpJobID), "sm jobs approve " + string(mcpJobID) + " --plan-hash "} {
		if !strings.Contains(r.stdout, want) {
			t.Errorf("stdout lacks %q:\n%s", want, r.stdout)
		}
	}
	if d.issueCalls() != 0 {
		t.Error("a token was issued before approval")
	}
	if _, err := os.Stat(dest); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("a destination file was created before approval (stat: %v)", err)
	}
}

func TestMCPClientsAddRegistrationAppliedIssuesTheToken(t *testing.T) {
	d := newMCPDaemon(t)
	d.register = func() wire.Direct[wire.MCPClient] {
		row := mcpClientRow(wire.MCPClientPendingToken, mcpMeID)
		return wire.Direct[wire.MCPClient]{Applied: &row}
	}
	dest := filepath.Join(t.TempDir(), "token")
	r := d.run(realMCPDeps(nil), "mcp", "clients", "add", "desk", "--token-file", dest)
	if r.code != 0 {
		t.Fatalf("code=%d stderr=%q", r.code, r.stderr)
	}
	if got, _ := os.ReadFile(dest); string(got) != mcpSecret {
		t.Errorf("file = %q", got)
	}
}

func TestMCPClientsAddPendingTokenIssuesIntoFileAndNeverPrintsIt(t *testing.T) {
	d := newMCPDaemon(t, mcpClientRow(wire.MCPClientPendingToken, mcpMeID))
	dest := filepath.Join(t.TempDir(), "token")
	for _, args := range [][]string{
		{"mcp", "clients", "add", "desk", "--token-file", dest},
	} {
		r := d.run(realMCPDeps(nil), args...)
		if r.code != 0 {
			t.Fatalf("code=%d stderr=%q", r.code, r.stderr)
		}
		if strings.Contains(r.stdout+r.stderr, mcpSecret) {
			t.Error("the token was printed")
		}
		if !strings.Contains(r.stdout, dest) {
			t.Errorf("stdout does not say where the token went:\n%s", r.stdout)
		}
	}
	if got, _ := os.ReadFile(dest); string(got) != mcpSecret {
		t.Errorf("file = %q", got)
	}
	if info, _ := os.Stat(dest); info.Mode().Perm() != 0o600 {
		t.Errorf("mode = %v", info.Mode().Perm())
	}
	var issue sentRequest
	for _, req := range d.api.Requests() {
		if strings.HasSuffix(req.Path, "/token") {
			issue = req
		}
	}
	if !strings.Contains(issue.Body, "expires_at") || issue.Header.Get("Idempotency-Key") != "" {
		t.Errorf("issuance request = %+v", issue)
	}
}

func TestMCPClientsAddPendingTokenIssuesIntoKeychain(t *testing.T) {
	d := newMCPDaemon(t, mcpClientRow(wire.MCPClientPendingToken, mcpMeID))
	store := &sinkMemCredentials{location: "the keychain"}
	r := d.run(realMCPDeps(store), "mcp", "clients", "add", "desk", "--keychain", "desk-token")
	if r.code != 0 {
		t.Fatalf("code=%d stderr=%q", r.code, r.stderr)
	}
	if store.entries["desk-token"] != mcpSecret {
		t.Error("token not in the keychain")
	}
	if strings.Contains(r.stdout+r.stderr, mcpSecret) {
		t.Error("the token was printed")
	}
}

func TestMCPClientsAddDestinationRefusedBeforeIssuance(t *testing.T) {
	tests := []struct {
		name string
		deps func(t *testing.T) (mcpClientsDeps, []string)
	}{
		{"existing file", func(t *testing.T) (mcpClientsDeps, []string) {
			path := filepath.Join(t.TempDir(), "token")
			writeFile(t, path, "keep")
			return realMCPDeps(nil), []string{"--token-file", path}
		}},
		{"symlink", func(t *testing.T) (mcpClientsDeps, []string) {
			dir := t.TempDir()
			path := filepath.Join(dir, "token")
			if err := os.Symlink(filepath.Join(dir, "elsewhere"), path); err != nil {
				t.Fatal(err)
			}
			return realMCPDeps(nil), []string{"--token-file", path}
		}},
		{"group-writable directory", func(t *testing.T) (mcpClientsDeps, []string) {
			dir := t.TempDir()
			if err := os.Chmod(dir, 0o770); err != nil {
				t.Fatal(err)
			}
			return realMCPDeps(nil), []string{"--token-file", filepath.Join(dir, "token")}
		}},
		{"keychain unavailable", func(*testing.T) (mcpClientsDeps, []string) {
			return realMCPDeps(nil), []string{"--keychain", "desk-token"}
		}},
		{"keychain entry exists", func(*testing.T) (mcpClientsDeps, []string) {
			return realMCPDeps(&sinkMemCredentials{entries: map[string]string{"desk-token": "old"}}), []string{"--keychain", "desk-token"}
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d := newMCPDaemon(t, mcpClientRow(wire.MCPClientPendingToken, mcpMeID))
			deps, flags := tt.deps(t)
			r := d.run(deps, append([]string{"mcp", "clients", "add", "desk"}, flags...)...)
			if r.code != exitUsage {
				t.Errorf("exit = %d, want %d (stderr %q)", r.code, exitUsage, r.stderr)
			}
			if d.issueCalls() != 0 {
				t.Errorf("%d issuance calls, want none", d.issueCalls())
			}
		})
	}
}

func TestMCPClientsAddForeignOwnerDestinationRefusedBeforeIssuance(t *testing.T) {
	d := newMCPDaemon(t, mcpClientRow(wire.MCPClientPendingToken, mcpMeID))
	deps := realMCPDeps(nil)
	deps.openFileSink = func(path string) (tokenSink, error) {
		if err := checkTokenDir(filepath.Dir(path), os.Geteuid()+1); err != nil {
			return nil, err
		}
		return nil, errors.New("unreachable")
	}
	r := d.run(deps, "mcp", "clients", "add", "desk", "--token-file", filepath.Join(t.TempDir(), "token"))
	if r.code != exitUsage || d.issueCalls() != 0 {
		t.Errorf("exit=%d issuance calls=%d", r.code, d.issueCalls())
	}
}

func TestMCPClientsAddStorageFailureAfterIssuance(t *testing.T) {
	faults := map[string]func(*os.File) tokenFile{
		"short write": func(f *os.File) tokenFile { return &sinkFaultyFile{file: f, shortWrite: true} },
		"ENOSPC":      func(f *os.File) tokenFile { return &sinkFaultyFile{file: f, writeErr: syscall.ENOSPC} },
		"fsync":       func(f *os.File) tokenFile { return &sinkFaultyFile{file: f, syncErr: syscall.EIO} },
	}
	for name, fault := range faults {
		t.Run(name, func(t *testing.T) {
			d := newMCPDaemon(t, mcpClientRow(wire.MCPClientPendingToken, mcpMeID))
			dest := filepath.Join(t.TempDir(), "token")
			deps := realMCPDeps(nil)
			deps.openFileSink = func(path string) (tokenSink, error) {
				sink, err := openFileSink(path)
				if err != nil {
					return nil, err
				}
				sink.out = fault(sink.out.(*os.File))
				return sink, nil
			}
			r := d.run(deps, "mcp", "clients", "add", "desk", "--token-file", dest)
			wantMessage := "the token for desk (" + string(mcpClientID) + ") was issued but could not be stored: "
			wantTail := "; it cannot be shown again — run 'sm mcp clients remove " + string(mcpClientID) + "' and add it again"
			if r.code != exitInternal || !strings.Contains(r.stderr, wantMessage) || !strings.Contains(r.stderr, wantTail) {
				t.Errorf("exit=%d stderr=%q", r.code, r.stderr)
			}
			if _, err := os.Stat(dest); !errors.Is(err, os.ErrNotExist) {
				t.Errorf("partial file left behind (stat: %v)", err)
			}
			if strings.Contains(r.stdout+r.stderr, mcpSecret) {
				t.Error("the token was printed")
			}
		})
	}
}

func TestMCPClientsAddKeychainPutFailureAfterIssuance(t *testing.T) {
	d := newMCPDaemon(t, mcpClientRow(wire.MCPClientPendingToken, mcpMeID))
	store := &sinkMemCredentials{setErr: errors.New("keychain locked")}
	r := d.run(realMCPDeps(store), "mcp", "clients", "add", "desk", "--keychain", "desk-token")
	want := "the token for desk (" + string(mcpClientID) + ") was issued but could not be stored: "
	if r.code != exitInternal || !strings.Contains(r.stderr, want) || !strings.Contains(r.stderr, "sm mcp clients remove "+string(mcpClientID)) {
		t.Errorf("exit=%d stderr=%q", r.code, r.stderr)
	}
	if d.issueCalls() != 1 {
		t.Errorf("issuance calls = %d, want 1", d.issueCalls())
	}
}

func TestMCPClientsAddActiveIsNotReissued(t *testing.T) {
	d := newMCPDaemon(t, mcpClientRow(wire.MCPClientActive, mcpMeID))
	dest := filepath.Join(t.TempDir(), "token")
	r := d.run(realMCPDeps(nil), "mcp", "clients", "add", "desk", "--token-file", dest)
	want := "desk is already active; its token was issued at 2026-10-01T13:00:00Z and is not re-issued. If you do not hold it, remove and add the client again."
	if r.code != exitInternal || !strings.Contains(r.stderr, want) {
		t.Errorf("exit=%d stderr=%q", r.code, r.stderr)
	}
	if d.issueCalls() != 0 {
		t.Error("an active client was issued a second token")
	}
	if _, err := os.Stat(dest); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("a file was created (stat: %v)", err)
	}
}

func TestMCPClientsAddFailedIssuanceLeavesNoFile(t *testing.T) {
	tests := []struct {
		name   string
		status int
		code   smerr.Code
		reason smerr.Reason
	}{
		{"window expired", 409, smerr.CodeConflict, smerr.ReasonIssuanceWindowExpired},
		{"not the requester", 403, smerr.CodePolicyDenied, smerr.ReasonNotPlanActor},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d := newMCPDaemon(t, mcpClientRow(wire.MCPClientPendingToken, mcpMeID))
			d.issueErr = func(w http.ResponseWriter) { replyError(w, tt.status, tt.code, tt.reason, "refused") }
			dest := filepath.Join(t.TempDir(), "token")
			r := d.run(realMCPDeps(nil), "mcp", "clients", "add", "desk", "--token-file", dest)
			if r.code != exitInternal || !strings.Contains(r.stderr, "refused") {
				t.Errorf("exit=%d stderr=%q", r.code, r.stderr)
			}
			if _, err := os.Stat(dest); !errors.Is(err, os.ErrNotExist) {
				t.Errorf("destination left behind (stat: %v)", err)
			}
		})
	}
}

func TestMCPClientsAddForeignRequesterIsRefusedBeforeIssuance(t *testing.T) {
	d := newMCPDaemon(t, mcpClientRow(wire.MCPClientPendingToken, mcpOtherID))
	dest := filepath.Join(t.TempDir(), "token")
	r := d.run(realMCPDeps(nil), "mcp", "clients", "add", "desk", "--token-file", dest)
	if r.code != exitInternal || !strings.Contains(r.stderr, "only the requester") {
		t.Errorf("exit=%d stderr=%q", r.code, r.stderr)
	}
	if d.issueCalls() != 0 {
		t.Error("issuance attempted for another identity's client")
	}
	if _, err := os.Stat(dest); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("destination created (stat: %v)", err)
	}
}

func TestMCPClientsAddRejectsBadFlagsBeforeConnecting(t *testing.T) {
	tests := map[string][]string{
		"no destination":   {"mcp", "clients", "add", "desk"},
		"two destinations": {"mcp", "clients", "add", "desk", "--token-file", "f", "--keychain", "k"},
		"expiry over 365d": {"mcp", "clients", "add", "desk", "--keychain", "k", "--expires", "400d"},
		"expiry garbage":   {"mcp", "clients", "add", "desk", "--keychain", "k", "--expires", "soon"},
	}
	for name, args := range tests {
		t.Run(name, func(t *testing.T) {
			d := newMCPDaemon(t, mcpClientRow(wire.MCPClientPendingToken, mcpMeID))
			r := d.run(realMCPDeps(&sinkMemCredentials{}), args...)
			if r.code != exitUsage || len(d.api.Requests()) != 0 {
				t.Errorf("exit=%d requests=%d", r.code, len(d.api.Requests()))
			}
		})
	}
}

func TestMCPClientsRemoveByNameAndByID(t *testing.T) {
	for _, ref := range []string{"desk", string(mcpClientID)} {
		t.Run(ref, func(t *testing.T) {
			d := newMCPDaemon(t, mcpClientRow(wire.MCPClientActive, mcpMeID))
			r := d.run(realMCPDeps(nil), "mcp", "clients", "remove", ref)
			if r.code != 0 || !strings.Contains(r.stdout, "removed MCP client desk") {
				t.Fatalf("code=%d out=%q err=%q", r.code, r.stdout, r.stderr)
			}
			muts := d.api.Mutations()
			if len(muts) != 1 || muts[0].Method != "DELETE" {
				t.Errorf("mutations = %+v", muts)
			}
		})
	}
}

func TestMCPClientsRemoveUnknownName(t *testing.T) {
	d := newMCPDaemon(t, mcpClientRow(wire.MCPClientActive, mcpMeID))
	r := d.run(realMCPDeps(nil), "mcp", "clients", "remove", "ghost")
	if r.code != exitInternal || !strings.Contains(r.stderr, `no MCP client named "ghost"`) || len(d.api.Mutations()) != 0 {
		t.Errorf("exit=%d stderr=%q mutations=%d", r.code, r.stderr, len(d.api.Mutations()))
	}
}
