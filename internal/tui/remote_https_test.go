package tui_test

import (
	"context"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	tea "charm.land/bubbletea/v2"

	"github.com/autarquico/supermgmt/internal/api/wire"
	"github.com/autarquico/supermgmt/internal/client"
	"github.com/autarquico/supermgmt/internal/domain"
	"github.com/autarquico/supermgmt/internal/tui"
)

var ansi = regexp.MustCompile("\x1b\\[[0-9;:?]*[ -/]*[@-~]")

func send[T any](w http.ResponseWriter, data T) {
	w.Header().Set("Content-Type", wire.ContentType)
	_ = json.NewEncoder(w).Encode(wire.Envelope[T]{Data: data})
}

// remoteControlPlane serves what the TUI loads at start over HTTPS, and one
// event on the stream, to the holder of token. It returns the server's URL and
// the CA file that vouches for it.
func remoteControlPlane(t *testing.T, token string) (url, caFile string) {
	t.Helper()
	mux := http.NewServeMux()
	guard := func(h http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			if r.Header.Get("Authorization") != "Bearer "+token {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			h(w, r)
		}
	}
	mux.HandleFunc("GET "+wire.PathMe, guard(func(w http.ResponseWriter, _ *http.Request) {
		send(w, wire.Me{DisplayName: "alex", InstanceMode: "server", Roles: []string{"admin"}, Credential: domain.CredentialSession})
	}))
	mux.HandleFunc("GET "+wire.PathNodes, guard(func(w http.ResponseWriter, _ *http.Request) {
		send(w, wire.Page[wire.Node]{Items: []wire.Node{{
			ID: "0192a000-0000-7000-8000-00000000a001", Name: "web-1", Provider: "ssh", Kind: "ssh",
			Reachability: domain.ReachabilityReachable, ManagementState: domain.ManagementManaged,
		}}})
	}))
	mux.HandleFunc("GET "+wire.PathApprovals, guard(func(w http.ResponseWriter, _ *http.Request) { send(w, wire.Page[wire.Approval]{}) }))
	mux.HandleFunc("GET "+wire.PathJobs, guard(func(w http.ResponseWriter, _ *http.Request) { send(w, wire.Page[wire.Job]{}) }))
	mux.HandleFunc("GET "+wire.PathProviders, guard(func(w http.ResponseWriter, _ *http.Request) {
		send(w, wire.Page[wire.Provider]{Items: []wire.Provider{{Type: "ssh", Name: "ssh", Origin: domain.ProviderStatic, Status: "ready"}}})
	}))
	mux.HandleFunc("GET "+wire.PathEventStream, guard(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", wire.ContentTypeEventStream)
		data, _ := json.Marshal(wire.Event{Seq: 9, Action: "node.probe"})
		_, _ = fmt.Fprintf(w, "id: 9\nevent: event\ndata: %s\n\n", data)
		w.(http.Flusher).Flush()
		<-r.Context().Done()
	}))
	srv := httptest.NewTLSServer(mux)
	t.Cleanup(srv.Close)
	caFile = filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(caFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw}), 0o600); err != nil {
		t.Fatal(err)
	}
	return srv.URL, caFile
}

func signedIn(t *testing.T, url, caFile, token string) *client.Client {
	t.Helper()
	api, err := client.NewRemote(client.Remote{URL: url, CAFile: caFile, Token: token}, client.Options{})
	if err != nil {
		t.Fatal(err)
	}
	return api
}

// settle runs cmd and everything it leads to, like the Bubble Tea runtime.
func settle(t *testing.T, m *tui.Model, cmd tea.Cmd) {
	t.Helper()
	queue := []tea.Cmd{cmd}
	for len(queue) > 0 {
		c := queue[0]
		queue = queue[1:]
		if c == nil {
			continue
		}
		msg := c()
		if batch, ok := msg.(tea.BatchMsg); ok {
			queue = append(queue, batch...)
			continue
		}
		_, next := m.Update(msg)
		queue = append(queue, next)
	}
}

func screenOf(m *tui.Model) string { return ansi.ReplaceAllString(m.View().Content, "") }

func TestTUIShowsARemoteServersNodesOverHTTPS(t *testing.T) {
	url, ca := remoteControlPlane(t, "smt_remote_token_0123456789")
	api := signedIn(t, url, ca, "smt_remote_token_0123456789")
	m := tui.New(api, tui.Options{Timeout: 5 * time.Second, Location: time.UTC, Settings: tui.Settings{Profile: "home", Server: url}})
	_, _ = m.Update(tea.WindowSizeMsg{Width: 100, Height: 28})

	settle(t, m, m.Init())
	_, cmd := m.Update(tea.KeyPressMsg{Code: '2', Text: "2"})
	settle(t, m, cmd)

	view := screenOf(m)
	for _, want := range []string{"Resources", "web-1", "1 node"} {
		if !strings.Contains(view, want) {
			t.Errorf("the remote view lacks %q:\n%s", want, view)
		}
	}
	_, cmd = m.Update(tea.KeyPressMsg{Code: '7', Text: "7"})
	settle(t, m, cmd)
	view = screenOf(m)
	for _, want := range []string{"Settings", "home", url, "alex", "server"} {
		if !strings.Contains(view, want) {
			t.Errorf("Settings lacks %q:\n%s", want, view)
		}
	}
}

func TestTUIWithARevokedTokenShowsTheFailureAndHowToFixIt(t *testing.T) {
	url, ca := remoteControlPlane(t, "smt_the_real_token_000000000")
	api := signedIn(t, url, ca, "smt_revoked_token_000000000")
	m := tui.New(api, tui.Options{Timeout: 5 * time.Second, Location: time.UTC})
	_, _ = m.Update(tea.WindowSizeMsg{Width: 100, Height: 28})

	settle(t, m, m.Init())

	view := screenOf(m)
	if !strings.Contains(view, "error") || !strings.Contains(view, "sm login") {
		t.Errorf("the screen does not say the credential was refused:\n%s", view)
	}
}

func TestTUILiveStreamOverHTTPSDeliversEvents(t *testing.T) {
	url, ca := remoteControlPlane(t, "smt_remote_token_0123456789")
	api := signedIn(t, url, ca, "smt_remote_token_0123456789")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	got := make(chan wire.Event, 1)

	go func() {
		_ = api.FollowEvents(ctx, wire.EventQuery{}, func(e wire.Event) error {
			got <- e
			cancel()
			return nil
		})
	}()

	select {
	case e := <-got:
		if e.Seq != 9 || e.Action != "node.probe" {
			t.Errorf("event = %+v", e)
		}
	case <-ctx.Done():
		t.Fatal("no event arrived")
	}
}
