package daemon

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/autarquico/supermgmt/internal/api/wire"
	"github.com/autarquico/supermgmt/internal/app"
	"github.com/autarquico/supermgmt/internal/config"
	"github.com/autarquico/supermgmt/internal/database"
	"github.com/autarquico/supermgmt/internal/domain"
	"github.com/autarquico/supermgmt/internal/jobs"
)

// serverInstance is a data dir and a server-mode configuration whose HTTPS
// listener (plain HTTP behind an imaginary proxy) takes a free port.
type serverInstance struct {
	t     *testing.T
	root  string
	file  string
	cfg   *config.Config
	admin string
}

func newServerInstance(t *testing.T, extra string) *serverInstance {
	t.Helper()
	root, err := os.MkdirTemp("", "sms")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(root) })
	admin := filepath.Join(root, "run", "admin.sock")
	yaml := "version: 1\ninstance:\n  mode: server\n  data_dir: " + filepath.Join(root, "data") + "\n" +
		"server:\n  listen: 127.0.0.1:0\n  admin_socket: " + admin + "\n  trusted_proxies: [10.0.0.0/8]\n" +
		"security:\n  allow_self_approval: true\n" + extra
	file := filepath.Join(root, "config.yaml")
	if err := os.WriteFile(file, []byte(yaml), 0o600); err != nil {
		t.Fatal(err)
	}
	res, err := config.Load(file, []string{"HOME=" + root})
	if err != nil {
		t.Fatal(err)
	}
	return &serverInstance{t: t, root: root, file: file, cfg: res.Config, admin: admin}
}

func (i *serverInstance) dataDir() string { return i.cfg.Instance.DataDir }

// runningServer is a server started in this process.
type runningServer struct {
	t      *testing.T
	stop   context.CancelFunc
	done   chan error
	ep     Endpoints
	client *http.Client
	admin  *http.Client
}

func (i *serverInstance) start(opts ...func(*Options)) *runningServer {
	i.t.Helper()
	r, ready := i.startAsync(opts...)
	select {
	case <-ready:
	case err := <-r.done:
		r.stop()
		r.done <- err
		return r
	case <-time.After(waitLimit):
		failWithGoroutines(i.t, "the server did not start")
	}
	i.t.Cleanup(func() {
		r.stop()
		_ = r.wait()
	})
	return r
}

// startAsync starts RunServer and returns before it is serving; ready is
// closed when it is.
func (i *serverInstance) startAsync(opts ...func(*Options)) (*runningServer, <-chan struct{}) {
	ctx, cancel := context.WithCancel(context.Background())
	ready := make(chan struct{})
	rs := &runningServer{t: i.t, stop: cancel, done: make(chan error, 1)}
	o := Options{
		Config: i.cfg, ConfigFile: i.file, IdleCheck: 10 * time.Millisecond,
		OnServing: func(ep Endpoints) { rs.ep = ep; close(ready) },
	}
	for _, f := range opts {
		f(&o)
	}
	go func() { rs.done <- RunServer(ctx, o) }()
	rs.client = &http.Client{Timeout: 10 * time.Second}
	rs.admin = &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "unix", i.admin)
		},
	}}
	i.t.Cleanup(rs.client.CloseIdleConnections)
	return rs, ready
}

func (r *runningServer) wait() error {
	select {
	case err := <-r.done:
		r.done <- err
		return err
	case <-time.After(waitLimit):
		failWithGoroutines(r.t, "the server did not exit")
		return nil
	}
}

// call sends a request to the HTTPS listener.
func (r *runningServer) call(method, path, token, body string, headers ...string) (int, []byte) {
	r.t.Helper()
	return send(r.t, r.client, method, "http://"+r.ep.HTTP.String()+path, token, body, headers...)
}

// callAdmin sends a request to the admin socket.
func (r *runningServer) callAdmin(method, path, body string) (int, []byte) {
	r.t.Helper()
	return send(r.t, r.admin, method, "http://admin"+path, "", body)
}

func send(t *testing.T, c *http.Client, method, url, token, body string, headers ...string) (int, []byte) {
	t.Helper()
	var reader io.Reader = http.NoBody
	if body != "" {
		reader = bytes.NewBufferString(body)
	}
	req, err := http.NewRequestWithContext(context.Background(), method, url, reader)
	if err != nil {
		t.Fatal(err)
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	for i := 0; i+1 < len(headers); i += 2 {
		req.Header.Set(headers[i], headers[i+1])
	}
	resp, err := c.Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, url, err)
	}
	defer func() { _ = resp.Body.Close() }()
	payload, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	return resp.StatusCode, payload
}

// decodeData unwraps {"data":…}.
func decodeData[T any](t *testing.T, body []byte) T {
	t.Helper()
	var env wire.Envelope[T]
	if err := json.Unmarshal(body, &env); err != nil {
		t.Fatalf("not an envelope: %s", body)
	}
	return env.Data
}

// bootstrap issues a code over the admin socket and exchanges it over HTTPS;
// the result is the first admin's API token.
func (r *runningServer) bootstrap() wire.Bootstrapped {
	r.t.Helper()
	status, body := r.callAdmin(http.MethodPost, wire.AdminPathBootstrapCode, "")
	if status != http.StatusOK {
		r.t.Fatalf("bootstrap-code: %d %s", status, body)
	}
	code := decodeData[wire.BootstrapCodeIssued](r.t, body).Code
	status, body = r.call(http.MethodPost, wire.PathBootstrap, "", `{"code":"`+code+`","display_name":"Root"}`)
	if status != http.StatusOK {
		r.t.Fatalf("bootstrap exchange: %d %s", status, body)
	}
	return decodeData[wire.Bootstrapped](r.t, body)
}

// openDB opens the instance's database while no server runs.
func (i *serverInstance) openDB() *database.DB {
	i.t.Helper()
	db, err := database.Open(context.Background(), i.cfg.Storage.SQLite.Path, database.Options{})
	if err != nil {
		i.t.Fatal(err)
	}
	i.t.Cleanup(func() { _ = db.Close() })
	return db
}

func (i *serverInstance) setHold(held bool) {
	i.t.Helper()
	db := i.openDB()
	err := db.WithWriteTx(context.Background(), func(ctx context.Context, tx *database.Tx) error {
		return database.SetRestoreHold(ctx, tx, held, clockNow())
	})
	if err != nil {
		i.t.Fatal(err)
	}
	_ = db.Close()
}

// submitBackupWhileStopped queues a scheduled backup.create job as the system
// identity, the way the scheduler does, with no daemon running.
func (i *serverInstance) submitBackupWhileStopped() domain.ID {
	i.t.Helper()
	ctx := context.Background()
	db := i.openDB()
	defer func() { _ = db.Close() }()
	o, err := Options{Config: i.cfg, ConfigFile: i.file}.withDefaults()
	if err != nil {
		i.t.Fatal(err)
	}
	cfg, _, err := appConfig(db, o)
	if err != nil {
		i.t.Fatal(err)
	}
	reval, err := app.NewRevalidator(cfg)
	if err != nil {
		i.t.Fatal(err)
	}
	store, err := jobs.NewStore(jobs.Config{DB: db, Clock: o.Clock, IDs: o.IDs, Revalidator: reval, LockPlanner: app.LockPlanner{}})
	if err != nil {
		i.t.Fatal(err)
	}
	plans, err := app.NewPlans(cfg, store)
	if err != nil {
		i.t.Fatal(err)
	}
	queries, err := app.NewQueries(cfg, store, config.ModeServer)
	if err != nil {
		i.t.Fatal(err)
	}
	kit, err := openSecrets(ctx, i.cfg, db, o.Clock, o.IDs)
	if err != nil {
		i.t.Fatal(err)
	}
	service, err := app.NewBackupService(cfg, plans, queries, store, app.BackupOptions{
		Directory: i.cfg.Backup.Directory, Retention: i.cfg.Backup.Retention, KnownHostsPath: i.cfg.SSH.KnownHostsFile, SMVersion: "test", Keys: kit.keys,
	})
	if err != nil {
		i.t.Fatal(err)
	}
	sub, err := service.SubmitScheduled(ctx, SystemIdentityID)
	if err != nil {
		i.t.Fatal(err)
	}
	return sub.Job.ID
}

func (i *serverInstance) jobState(id domain.ID) domain.JobState {
	i.t.Helper()
	db := i.openDB()
	defer func() { _ = db.Close() }()
	var state domain.JobState
	if err := db.Reader().QueryRowContext(context.Background(), `SELECT state FROM jobs WHERE id = ?`, id).Scan(&state); err != nil {
		i.t.Fatal(err)
	}
	return state
}

func (i *serverInstance) archives() []string {
	matches, _ := filepath.Glob(filepath.Join(i.cfg.Backup.Directory, "supermgmt-*.tar.zst"))
	return matches
}

// clockNow is the wall clock the daemon under test runs on.
func clockNow() time.Time { return domain.SystemClock{}.Now() }
