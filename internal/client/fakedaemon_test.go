package client_test

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/autarquico/supermgmt/internal/api/wire"
	"github.com/autarquico/supermgmt/internal/client"
	smerr "github.com/autarquico/supermgmt/internal/errors"
)

const (
	fakeDaemonEnv = "SM_CLIENT_TEST_FAKE_DAEMON"
	stopMarker    = "stop"
)

// TestMain doubles as the autostarted daemon: when the spawned test binary
// finds fakeDaemonEnv it serves the socket named there until a stop marker
// appears next to it, instead of running tests.
func TestMain(m *testing.M) {
	if socket := os.Getenv(fakeDaemonEnv); socket != "" {
		os.Exit(serveFakeDaemon(socket))
	}
	os.Exit(m.Run())
}

func serveFakeDaemon(socket string) int {
	listener, err := (&net.ListenConfig{}).Listen(context.Background(), "unix", socket)
	if err != nil {
		return 2
	}
	println("fake-daemon-started")
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(wire.Envelope[wire.Me]{Data: wire.Me{DisplayName: "autostarted"}})
	})}
	go func() { _ = srv.Serve(listener) }()
	for {
		if _, err := os.Stat(filepath.Join(filepath.Dir(socket), stopMarker)); err == nil {
			_ = srv.Close()
			return 0
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// received is one request as the fake daemon saw it.
type received struct {
	Method, Path, Query string
	Header              http.Header
	Body                []byte
}

type fakeDaemon struct {
	Socket string

	mu       sync.Mutex
	requests []received
}

// startFakeDaemon serves handler on a fresh Unix socket. The socket lives in a
// short temp dir because sun_path is limited to 104 bytes on macOS.
func startFakeDaemon(t *testing.T, handler http.HandlerFunc) *fakeDaemon {
	t.Helper()
	dir, err := os.MkdirTemp("", "smc")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	f := &fakeDaemon{Socket: filepath.Join(dir, "s")}
	listener, err := (&net.ListenConfig{}).Listen(context.Background(), "unix", f.Socket)
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.record(r)
		handler(w, r)
	}))
	srv.Listener = listener
	srv.Start()
	t.Cleanup(srv.Close)
	return f
}

func (f *fakeDaemon) record(r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	f.mu.Lock()
	defer f.mu.Unlock()
	f.requests = append(f.requests, received{r.Method, r.URL.Path, r.URL.RawQuery, r.Header.Clone(), body})
}

// shortDir is a temp dir whose path leaves room for a socket name.
func shortDir(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "smc")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	return dir
}

func (f *fakeDaemon) Requests() []received {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]received(nil), f.requests...)
}

func (f *fakeDaemon) client(opts client.Options) *client.Client {
	opts.Socket = f.Socket
	return client.New(opts)
}

func respond[T any](w http.ResponseWriter, status int, data T) {
	w.Header().Set("Content-Type", wire.ContentType)
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(wire.Envelope[T]{Data: data, Meta: wire.Meta{CorrelationID: "corr-1"}})
}

func respondError(w http.ResponseWriter, status int, code smerr.Code, reason smerr.Reason, message string) {
	w.Header().Set("Content-Type", wire.ContentType)
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(wire.ErrorEnvelope{Error: wire.Error{
		Code: code, Message: message, CorrelationID: "corr-err",
		Details: map[string]any{wire.DetailReason: string(reason)},
	}})
}
