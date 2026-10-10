package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/spf13/cobra"

	"github.com/autarquico/supermgmt/internal/api/wire"
	smerr "github.com/autarquico/supermgmt/internal/errors"
)

// sentRequest is one request as the fake daemon saw it.
type sentRequest struct {
	Method, Path, Query string
	Header              http.Header
	Body                string
}

// fakeAPI is a daemon stand-in on a Unix socket plus the config and
// environment that make the CLI dial it. Autostart is off, so a missing
// daemon is an error instead of a spawned process.
type fakeAPI struct {
	Args []string // leading flags: --config <file>
	Env  []string

	mu       sync.Mutex
	requests []sentRequest
}

// newFakeAPI serves handler; a nil handler leaves the socket unserved.
func newFakeAPI(t *testing.T, handler http.HandlerFunc) *fakeAPI {
	t.Helper()
	dir, err := os.MkdirTemp("", "smcli") // short: sun_path is 104 bytes on macOS
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	socket := filepath.Join(dir, "s")
	configFile := filepath.Join(dir, "config.yaml")
	writeFile(t, configFile, "version: 1\ninstance:\n  name: test\n  mode: local\n  data_dir: "+filepath.Join(dir, "data")+"\ndaemon:\n  socket: "+socket+"\n")
	f := &fakeAPI{
		Args: []string{"--config", configFile},
		Env:  []string{"HOME=" + dir, envNoAutostart + "=1"},
	}
	if handler == nil {
		return f
	}
	listener, err := (&net.ListenConfig{}).Listen(context.Background(), "unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		f.mu.Lock()
		f.requests = append(f.requests, sentRequest{r.Method, r.URL.Path, r.URL.RawQuery, r.Header.Clone(), string(body)})
		f.mu.Unlock()
		handler(w, r)
	}))
	srv.Listener = listener
	srv.Start()
	t.Cleanup(srv.Close)
	return f
}

func (f *fakeAPI) Requests() []sentRequest {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]sentRequest(nil), f.requests...)
}

// Mutations are the requests that are not reads.
func (f *fakeAPI) Mutations() []sentRequest {
	var out []sentRequest
	for _, r := range f.Requests() {
		if r.Method != "GET" && r.Path != wire.PathNodesSSHHostKey {
			out = append(out, r)
		}
	}
	return out
}

// run executes args like the sm binary would, with only the client commands
// registered (the root registers them at merge time).
func (f *fakeAPI) run(args ...string) result {
	return f.runCtx(context.Background(), "", args...)
}

func (f *fakeAPI) runCtx(ctx context.Context, stdin string, args ...string) result {
	root := &cobra.Command{Use: "sm", SilenceUsage: true, SilenceErrors: true, Args: noArgs}
	root.SetFlagErrorFunc(func(_ *cobra.Command, err error) error { return usageErrorf("%s", err) })
	root.PersistentFlags().String("config", "", "")
	root.PersistentFlags().Bool("json", false, "")
	root.PersistentFlags().String("log-level", "info", "")
	root.AddCommand(clientCommands(f.Env)...) //nolint:contextcheck // finish() deliberately ends sessions on a fresh context

	var out, errOut bytes.Buffer
	root.SetIn(strings.NewReader(stdin))
	root.SetOut(&out)
	root.SetErr(&errOut)
	root.SetArgs(append(append([]string{}, f.Args...), args...))
	err := root.ExecuteContext(ctx)
	if err != nil {
		asJSON, _ := root.PersistentFlags().GetBool("json")
		reportError(&errOut, err, asJSON)
	}
	return result{exitCode(err), out.String(), errOut.String()}
}

func reply[T any](w http.ResponseWriter, status int, data T) {
	w.Header().Set("Content-Type", wire.ContentType)
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(wire.Envelope[T]{Data: data, Meta: wire.Meta{CorrelationID: "corr-ok"}})
}

func replyError(w http.ResponseWriter, status int, code smerr.Code, reason smerr.Reason, message string) {
	w.Header().Set("Content-Type", wire.ContentType)
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(wire.ErrorEnvelope{Error: wire.Error{
		Code: code, Message: message, CorrelationID: "corr-err",
		Details: map[string]any{wire.DetailReason: string(reason)},
	}})
}

// router dispatches on "METHOD path"; unknown routes are 404s so a wrong
// request fails the test instead of passing silently.
func router(routes map[string]http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if h, ok := routes[r.Method+" "+r.URL.Path]; ok {
			h(w, r)
			return
		}
		replyError(w, 404, smerr.CodeNotFound, "", "no route "+r.Method+" "+r.URL.Path)
	}
}
