//go:build e2e

package e2e_test

import (
	"context"
	"fmt"
	"regexp"
	"testing"
	"time"

	"github.com/autarquico/supermgmt/internal/api/wire"
	"github.com/autarquico/supermgmt/internal/domain"
	"github.com/autarquico/supermgmt/test/e2e/harness"
)

// idp is the identity provider shared by the servers of one test: Dex on a private docker network.
type idp struct {
	net *harness.Network
	ca  *harness.CA
	dex *harness.Dex
}

func newIdP(t *testing.T) *idp {
	t.Helper()
	net := harness.NewNetwork(t)
	ca := harness.NewCA(t)
	return &idp{net: net, ca: ca, dex: harness.StartDex(t, net, ca)}
}

// operator is a server whose first administrator is the Dex user admin@example.com.
type operator struct {
	srv   *harness.Server
	admin *harness.Client // the administrator's laptop
}

// startOperated starts a server, points it at the Dex of w and makes the Dex user its first
// administrator (spec 11.5): sign in with the IdP, then present the bootstrap code.
func (w *idp) startOperated(t *testing.T, mode harness.TLSMode) *operator {
	t.Helper()
	ctx := context.Background()
	srv := harness.StartServer(t, w.net, w.ca, harness.ServerOptions{Mode: mode, TrustCAs: []*harness.CA{w.ca}})
	srv.WaitReady(ctx)
	code := srv.IssueBootstrapCode(ctx)
	srv.EnableOIDC(ctx, w.dex)
	admin := harness.NewClient(t)
	admin.AddProfile(ctx, "ops", srv.URL, srv.CAFile)
	w.loginWithBrowser(t, srv, admin, harness.DexUser)
	admin.Must(ctx, code+"\n", "login", "--bootstrap")
	return &operator{srv: srv, admin: admin}
}

// person is someone with a laptop: a client with a profile for the server.
func (o *operator) person(t *testing.T) *harness.Client {
	t.Helper()
	c := harness.NewClient(t)
	c.AddProfile(context.Background(), "ops", o.srv.URL, o.srv.CAFile)
	return c
}

var (
	authURLLine  = regexp.MustCompile(`^\s+(https://\S+)$`)
	deviceCode   = regexp.MustCompile(`enter the code\s+(\S+)`)
	loginTimeout = 60 * time.Second
)

// loginWithBrowser runs `sm login --callback-port` and signs in as the Dex user in a browser.
func (w *idp) loginWithBrowser(t *testing.T, srv *harness.Server, c *harness.Client, user string) wire.Me {
	t.Helper()
	ctx := context.Background()
	p := c.Start(ctx, "", "login", "--no-browser", "--callback-port", fmt.Sprint(w.dex.CallbackPort))
	authURL := p.WaitLine(t, authURLLine, loginTimeout)[1]
	status, err := w.dex.NewBrowser().As(user).SignIn(ctx, authURL)
	if err != nil || status != 200 {
		t.Fatalf("the browser did not reach the loopback callback: %d %v", status, err)
	}
	res, err := p.Wait(loginTimeout)
	if err != nil || res.Code != 0 {
		t.Fatalf("sm login exited %d: %v\n%s", res.Code, err, res.Output())
	}
	return whoami(t, srv, c)
}

// loginWithDeviceCode runs `sm login --device` and approves the code on "another device".
func (w *idp) loginWithDeviceCode(t *testing.T, srv *harness.Server, c *harness.Client) wire.Me {
	t.Helper()
	ctx := context.Background()
	p := c.Start(ctx, "", "login", "--device")
	uri := p.WaitLine(t, authURLLine, loginTimeout)[1]
	code := p.WaitLine(t, deviceCode, loginTimeout)[1]
	status, err := w.dex.NewBrowser().ApproveDevice(ctx, uri, code)
	if err != nil || status != 200 {
		t.Fatalf("the device was not approved: %d %v", status, err)
	}
	res, err := p.Wait(loginTimeout)
	if err != nil || res.Code != 0 {
		t.Fatalf("sm login --device exited %d: %v\n%s", res.Code, err, res.Output())
	}
	return whoami(t, srv, c)
}

func whoami(t *testing.T, srv *harness.Server, c *harness.Client) wire.Me {
	t.Helper()
	me, err := srv.Typed(c.StoredToken("ops")).Me(context.Background())
	if err != nil {
		t.Fatalf("the stored session is not accepted: %v", err)
	}
	return me
}

// jobOf extracts the job a command parked or queued.
func jobOf(t *testing.T, sub wire.Submission) domain.ID {
	t.Helper()
	if sub.Job.ID == "" {
		t.Fatalf("no job in %+v", sub)
	}
	return sub.Job.ID
}
