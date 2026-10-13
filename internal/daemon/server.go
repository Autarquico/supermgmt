package daemon

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/autarquico/supermgmt/internal/api"
	"github.com/autarquico/supermgmt/internal/config"
	"github.com/autarquico/supermgmt/internal/database"
)

const (
	sharedSocketMode  fs.FileMode = 0o660
	sharedSocketUmask             = 0o117
	adminDirMode      fs.FileMode = 0o750
)

// RunServer is the life of one server (spec §2.2, §23.1, ADR-0017). In order:
// take the database lock, load the TLS pair, assemble the services (restore
// recovery before the database opens, then the hold, which refuses the start
// when unreadable), bind the HTTPS listener and the admin socket, and serve
// until ctx ends. A server has no idle exit and creates no `local:<uid>`
// identity: its first admin comes from the bootstrap exchange.
func RunServer(ctx context.Context, o Options) error {
	o, err := o.withDefaults()
	if err != nil {
		return err
	}
	cfg := o.Config
	if cfg.Instance.Mode != config.ModeServer {
		return errors.New("daemon: instance.mode is local: start it with sm daemon")
	}
	lock, err := database.AcquireDatabaseLock(cfg.Storage.SQLite.Path)
	if err != nil {
		return err
	}
	defer func() { _ = lock.Release() }()
	certs, err := loadCertificates(cfg.Server.TLS)
	if err != nil {
		return err
	}
	sys, err := assemble(ctx, o)
	if err != nil {
		return err
	}
	defer func() { _ = sys.close() }()

	https, err := listenHTTPS(ctx, cfg.Server, certs)
	if err != nil {
		return err
	}
	admin, err := listenAdmin(ctx, o)
	if err != nil {
		_ = https.Close()
		return err
	}
	stopReload := certs.reloadOn(o.Reload, o.Log)
	defer stopReload()

	bounds := []bound{{name: "https", server: sys.remote, listener: https}, {name: "admin", server: sys.admin, listener: admin}}
	o.Log.Info("server listening", slog.String("listen", https.Addr().String()), slog.String("admin_socket", cfg.Server.AdminSocket))
	return serve(ctx, o, sys, bounds, func() {
		if o.OnServing != nil {
			o.OnServing(Endpoints{HTTP: https.Addr(), Admin: cfg.Server.AdminSocket})
		}
	})
}

func (b *builder) serverServers(services api.Services) (*api.Server, *api.AdminServer, error) {
	proxy, err := b.proxy()
	if err != nil {
		return nil, nil, err
	}
	resolver, err := b.bearerResolver()
	if err != nil {
		return nil, nil, err
	}
	remote, err := api.New(api.Options{
		Services: services, IDs: b.o.IDs, Resolver: resolver, GitHubWebhook: b.githubWebhook(), Proxy: proxy,
		DB: b.db, Clock: b.o.Clock, RequestTimeout: b.cfg.Server.RequestTimeout, Log: b.o.Log, Ready: b.ready(),
	})
	if err != nil {
		return nil, nil, err
	}
	admin, err := api.NewAdmin(api.AdminOptions{Auth: b.auth, Hold: b.hold, Doctor: b.doctor, IDs: b.o.IDs, Log: b.o.Log})
	if err != nil {
		return nil, nil, err
	}
	return remote, admin, nil
}

// proxy is the trust boundary of `server.tls.mode: proxy`; nil for direct TLS,
// where the TCP peer is the client.
func (b *builder) proxy() (*api.Proxy, error) {
	if b.cfg.Server.TLS.Mode != config.TLSProxy {
		return nil, nil
	}
	return api.NewProxy(b.cfg.Server.TrustedProxies)
}

// ---- TLS ----------------------------------------------------------------------

// certificates serves the operator's certificate pair in direct TLS mode and
// swaps it atomically on reload; a pair that fails to load keeps the old one.
// The zero value is proxy mode, where the daemon speaks plain HTTP.
type certificates struct {
	certFile, keyFile string

	mu   sync.RWMutex
	pair *tls.Certificate
}

func loadCertificates(c config.TLS) (*certificates, error) {
	if c.Mode != config.TLSDirect {
		return &certificates{}, nil
	}
	certs := &certificates{certFile: c.CertFile, keyFile: c.KeyFile}
	if err := certs.reload(); err != nil {
		return nil, err
	}
	return certs, nil
}

func (c *certificates) direct() bool { return c.certFile != "" }

func (c *certificates) reload() error {
	pair, err := tls.LoadX509KeyPair(c.certFile, c.keyFile)
	if err != nil {
		return fmt.Errorf("load the TLS certificate pair: %w", err)
	}
	c.mu.Lock()
	c.pair = &pair
	c.mu.Unlock()
	return nil
}

func (c *certificates) getCertificate(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.pair, nil
}

func (c *certificates) config() *tls.Config {
	return &tls.Config{MinVersion: tls.VersionTLS12, GetCertificate: c.getCertificate, NextProtos: []string{"http/1.1"}}
}

// reloadOn re-reads the pair every time signals fires, until the returned
// function is called.
func (c *certificates) reloadOn(signals <-chan struct{}, log *slog.Logger) (stop func()) {
	if !c.direct() || signals == nil {
		return func() {}
	}
	done := make(chan struct{})
	finished := make(chan struct{})
	go func() {
		defer close(finished)
		for {
			select {
			case <-done:
				return
			case <-signals:
				if err := c.reload(); err != nil {
					log.Error("TLS reload failed; keeping the previous certificate", slog.Any("error", err))
					continue
				}
				log.Info("TLS certificate reloaded")
			}
		}
	}()
	return func() {
		close(done)
		<-finished
	}
}

// ---- listeners ----------------------------------------------------------------

func listenHTTPS(ctx context.Context, s config.Server, certs *certificates) (net.Listener, error) {
	l, err := listenAddress(ctx, s.Listen)
	if err != nil {
		return nil, fmt.Errorf("listen on %s: %w", s.Listen, err)
	}
	if certs.direct() {
		return tls.NewListener(l, certs.config()), nil
	}
	return l, nil
}

// listenAddress listens on host:port, or on a Unix socket for "unix:<path>"
// and an absolute path (proxy mode behind a local reverse proxy).
func listenAddress(ctx context.Context, listen string) (net.Listener, error) {
	if path, isUnix := unixPath(listen); isUnix {
		return bindShared(ctx, path)
	}
	var lc net.ListenConfig
	return lc.Listen(ctx, "tcp", listen)
}

func unixPath(listen string) (string, bool) {
	if path, found := strings.CutPrefix(listen, "unix:"); found {
		return path, true
	}
	return listen, strings.HasPrefix(listen, "/")
}

// listenAdmin binds the admin socket, mode 0660, and admits root and the
// service user (spec §23.1). Anyone else is closed unread.
func listenAdmin(ctx context.Context, o Options) (net.Listener, error) {
	path := o.Config.Server.AdminSocket
	if err := CheckSocketPath(path); err != nil {
		return nil, err
	}
	if err := prepareAdminDir(filepath.Dir(path), int(o.UID)); err != nil {
		return nil, err
	}
	l, err := bindShared(ctx, path)
	if err != nil {
		return nil, fmt.Errorf("admin socket: %w", err)
	}
	return api.RestrictToUIDs(l, []uint32{0, o.UID}, o.Peer, o.Log), nil
}

// prepareAdminDir creates the directory of the admin socket and refuses one
// that someone else could replace the socket in: it must be a real directory
// owned by root or the service user and not writable by group or others.
func prepareAdminDir(dir string, uid int) error {
	if err := os.MkdirAll(dir, adminDirMode); err != nil {
		return fmt.Errorf("create the admin socket directory: %w", err)
	}
	info, err := os.Lstat(dir)
	if err != nil {
		return fmt.Errorf("inspect the admin socket directory: %w", err)
	}
	owner, ok := ownerOf(info)
	switch {
	case !info.IsDir():
		return &UnsafeSocketDirError{Dir: dir, Reason: "it is not a real directory (a symlink?)"}
	case !ok || (owner != 0 && owner != uid):
		return &UnsafeSocketDirError{Dir: dir, Reason: fmt.Sprintf("it is owned by uid %d, not root or the service user", owner)}
	case info.Mode().Perm()&0o022 != 0:
		return &UnsafeSocketDirError{Dir: dir, Reason: fmt.Sprintf("its mode %04o lets group or others replace the socket", info.Mode().Perm())}
	}
	return nil
}

// bindShared listens on a Unix socket reachable by its owner and group (mode
// 0660). The caller holds the database lock, the proof that no live daemon
// owns an old socket file.
func bindShared(ctx context.Context, path string) (net.Listener, error) {
	if err := unlinkStaleSocket(path); err != nil {
		return nil, err
	}
	l, err := listenMasked(ctx, path, sharedSocketUmask)
	if err != nil {
		return nil, err
	}
	if err := os.Chmod(path, sharedSocketMode); err != nil {
		_ = l.Close()
		return nil, fmt.Errorf("set the mode of %s: %w", path, err)
	}
	return l, nil
}
