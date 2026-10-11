package daemon

import (
	"context"
	"os"
	"os/exec"
	"sync/atomic"
	"testing"

	"github.com/autarquico/supermgmt/internal/api"
	"github.com/autarquico/supermgmt/internal/api/wire"
	"github.com/autarquico/supermgmt/internal/app"
	"github.com/autarquico/supermgmt/internal/domain/domaintest"
)

// countingAdmin counts the requests that reach the admin services.
type countingAdmin struct{ served atomic.Int64 }

func (c *countingAdmin) IssueBootstrapCode(context.Context, int) (wire.BootstrapCodeIssued, error) {
	c.served.Add(1)
	return wire.BootstrapCodeIssued{}, nil
}

func (c *countingAdmin) Grant(context.Context, int, wire.GrantRequest) error {
	c.served.Add(1)
	return nil
}
func (c *countingAdmin) Load(context.Context) (bool, error)              { return false, nil }
func (c *countingAdmin) Guard(context.Context, string, app.Caller) error { c.served.Add(1); return nil }

func (c *countingAdmin) Complete(context.Context, int) error { c.served.Add(1); return nil }

// The *PeerCred* tests run only where a second OS user exists (see
// peercred_test.go).
func TestAdminSocketRefusesAnotherUserPeerCred(t *testing.T) {
	user, _ := peerEnv(t)
	if _, err := exec.LookPath("perl"); err != nil {
		t.Skip("perl is needed to speak raw HTTP as the other user")
	}
	counted := &countingAdmin{}
	server, err := api.NewAdmin(api.AdminOptions{
		Auth: counted, Hold: counted, IDs: domaintest.NewSequentialIDs(),
		Doctor: func(context.Context) (wire.AdminDoctor, error) { counted.served.Add(1); return wire.AdminDoctor{}, nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	socket := openSocketDir(t)
	listener := api.RestrictToUIDs(listenOpen(t, socket), []uint32{0, uint32(os.Getuid())}, api.PeerUID, nil)
	go func() { _ = server.Serve(listener) }()
	t.Cleanup(func() { _ = server.Shutdown(context.Background()) })

	script := `use IO::Socket::UNIX; my $s = IO::Socket::UNIX->new(Peer => $ARGV[0]) or exit 3;
print $s "GET /admin/doctor HTTP/1.0\r\n\r\n"; my $got = <$s>; print defined $got ? "answered" : "closed";`
	out, err := exec.CommandContext(context.Background(), "sudo", "-n", "-u", user, "perl", "-e", script, socket).CombinedOutput()
	if err != nil {
		t.Fatalf("running as %s: %v: %s", user, err, out)
	}
	if string(out) != "closed" || counted.served.Load() != 0 {
		t.Errorf("output %q, %d requests served; want the connection closed unread", out, counted.served.Load())
	}
}
