package installer

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"io/fs"
	"math/big"
	"path"
	"slices"
	"sort"
	"strings"
	"testing"
	"time"
)

var testNow = time.Date(2026, 10, 11, 12, 0, 0, 0, time.UTC)

type fixedClock struct{}

func (fixedClock) Now() time.Time { return testNow }

// world is an in-memory host: it implements every seam and records the
// order of side effects in events.
type world struct {
	files    map[string][]byte
	modes    map[string]fs.FileMode
	owners   map[string]Owner
	users    map[string]bool
	events   []string
	commands []Command
	// failures and canned answers
	runErr     map[string]error // keyed by "name arg0 arg1"
	bootstrap  string
	healthErr  error
	probe      Probe
	startErr   error
	asked      []string
	confirmYes bool
}

func newWorld() *world {
	return &world{
		files: map[string][]byte{"/tmp/sm": []byte("binary")}, modes: map[string]fs.FileMode{}, owners: map[string]Owner{},
		users: map[string]bool{}, runErr: map[string]error{}, bootstrap: "CODE-1234\n", confirmYes: true,
	}
}

func (w *world) record(format string, args ...string) {
	w.events = append(w.events, format+strings.Join(args, " "))
}

func (w *world) Exists(p string) bool { _, ok := w.files[p]; return ok }
func (w *world) ReadFile(p string) ([]byte, error) {
	if b, ok := w.files[p]; ok {
		return b, nil
	}
	return nil, fs.ErrNotExist
}

func (w *world) MkdirAll(p string, m fs.FileMode, o Owner) error {
	w.modes[p], w.owners[p] = m, o
	w.record("mkdir ", p)
	return nil
}

func (w *world) WriteFile(p string, d []byte, m fs.FileMode, o Owner) error {
	w.files[p], w.modes[p], w.owners[p] = d, m, o
	w.record("write ", p)
	return nil
}

func (w *world) CopyFile(src, dst string, m fs.FileMode, o Owner) error {
	w.files[dst], w.modes[dst], w.owners[dst] = w.files[src], m, o
	w.record("copy ", dst)
	return nil
}
func (w *world) RemoveAll(p string) error { delete(w.files, p); return nil }

func (w *world) UserExists(n string) (bool, error) { return w.users[n], nil }
func (w *world) CreateServiceUser(_ context.Context, n, _ string) error {
	w.users[n] = true
	w.record("useradd ", n)
	return nil
}

type fakeServices struct {
	w      *world
	prefix string
}

func (s fakeServices) Register(_ context.Context, u Unit) error {
	s.w.record(s.prefix+"register ", u.Name)
	return nil
}

func (s fakeServices) Start(_ context.Context, u Unit) error {
	s.w.record(s.prefix+"start ", u.Name)
	return s.w.startErr
}

func (w *world) Run(_ context.Context, c Command) ([]byte, error) {
	w.commands = append(w.commands, c)
	key := c.Name + " " + strings.Join(c.Args[:min(2, len(c.Args))], " ")
	w.record("run ", key)
	if err := w.runErr[key]; err != nil {
		return nil, err
	}
	if len(c.Args) > 1 && c.Args[0] == "admin" {
		return []byte(w.bootstrap), nil
	}
	return nil, nil
}

func (w *world) WaitReady(_ context.Context, p Probe, _ time.Duration) error {
	w.probe = p
	w.record("health ", p.URL)
	return w.healthErr
}

func (w *world) Confirm(q string) (bool, error) {
	w.asked = append(w.asked, q)
	return w.confirmYes, nil
}

func (w *world) Ask(q string) (string, error) {
	w.asked = append(w.asked, q)
	return "https://mgmt.example.com", nil
}

func (w *world) deps(goos string, uid int, interactive bool) (Deps, *bytes.Buffer) {
	out := &bytes.Buffer{}
	d := Deps{
		Host:  Host{GOOS: goos, UID: uid, Home: "/home/alex", Env: map[string]string{}, HasSystemd: goos == "linux"},
		Files: w, Accounts: w, Runner: w, Health: w, Clock: fixedClock{}, Out: out,
		Services: fakeServices{w, ""}, UserServices: fakeServices{w, "user-"},
	}
	if interactive {
		d.Prompter = w
	}
	return d, out
}

func (w *world) index(prefix string) int {
	return slices.IndexFunc(w.events, func(e string) bool { return strings.HasPrefix(e, prefix) })
}

func exitCodeOf(t *testing.T, err error) int {
	t.Helper()
	var e *Error
	if !errors.As(err, &e) {
		t.Fatalf("want *installer.Error, got %v", err)
	}
	return e.Code
}

// testCert returns a PEM pair for host valid until notAfter.
func testCert(t *testing.T, host string, notAfter time.Time) (certPEM, keyPEM []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: host}, DNSNames: []string{host},
		NotBefore: testNow.Add(-72 * time.Hour), NotAfter: notAfter,
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
}

func (w *world) Lock(string) (func(), error) { return func() {}, nil }

func (w *world) Canonical(p string) (string, error) { return p, nil }

func (w *world) FreeBytes(string) (uint64, error) { return 1 << 40, nil }

func (w *world) FileSize(p string) (int64, error) {
	b, ok := w.files[p]
	if !ok {
		return 0, fs.ErrNotExist
	}
	return int64(len(b)), nil
}

func (w *world) ListDir(dir string) ([]string, error) {
	var names []string
	for p := range w.files {
		if path.Dir(p) == dir {
			names = append(names, path.Base(p))
		}
	}
	sort.Strings(names)
	return names, nil
}

func (w *world) Lstat(p string) (EntryInfo, error) {
	if _, ok := w.files[p]; !ok {
		return EntryInfo{}, fs.ErrNotExist
	}
	return EntryInfo{Regular: true, Mode: w.modes[p]}, nil
}
