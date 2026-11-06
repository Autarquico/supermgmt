// Command cloudflared-fake stands in for `cloudflared access ssh --hostname H`
// in the tunnel suites (ADR-0037). It records its argv and environment, then
// pipes its stdio to an SSH server, which is what the real carrier does once
// Cloudflare has admitted the service token.
//
// The dialler starts it with no PATH and a private HOME (the only place it
// can read its behaviour from), so everything it needs lives there:
//
//	$HOME/forward             host:port of the SSH server to bridge to (the fixture's sshd)
//	$HOME/record-<pid>.json   what this process was started with (argv, env)
//	$HOME/resolver            optional: the host names the system resolver answers, one per line. When it
//	                          exists the process looks its --hostname up there first, appends the name to
//	$HOME/lookups and exits 5 with "no such host" for one that is not listed, as the real
//	                          cloudflared does when the system resolver answers NXDOMAIN.
//
// A missing or empty forward file makes it exit 4 with a message, never a
// silent success.
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
)

type record struct {
	PID  int      `json:"pid"`
	Argv []string `json:"argv"`
	Env  []string `json:"env"`
}

func main() {
	home := os.Getenv("HOME")
	if home == "" {
		fmt.Fprintln(os.Stderr, "cloudflared-fake: HOME is not set")
		os.Exit(4)
	}
	rec, err := json.Marshal(record{PID: os.Getpid(), Argv: os.Args, Env: os.Environ()})
	if err == nil {
		err = os.WriteFile(filepath.Join(home, "record-"+strconv.Itoa(os.Getpid())+".json"), rec, 0o600)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "cloudflared-fake: record:", err)
		os.Exit(4)
	}
	if err := lookup(home, os.Args); err != nil {
		fmt.Fprintln(os.Stderr, "cloudflared-fake:", err)
		os.Exit(5)
	}
	raw, err := os.ReadFile(filepath.Join(home, "forward"))
	forward := strings.TrimSpace(string(raw))
	if err != nil || forward == "" {
		fmt.Fprintln(os.Stderr, "cloudflared-fake: no forward address")
		os.Exit(4)
	}
	conn, err := (&net.Dialer{}).DialContext(context.Background(), "tcp", forward)
	if err != nil {
		fmt.Fprintln(os.Stderr, "cloudflared-fake: dial:", err)
		os.Exit(4)
	}
	done := make(chan struct{}, 2)
	go func() { _, _ = io.Copy(conn, os.Stdin); done <- struct{}{} }()
	go func() { _, _ = io.Copy(os.Stdout, conn); done <- struct{}{} }()
	<-done
}

// lookup is the system resolver lookup of the tunnel hostname, when the test models one.
func lookup(home string, argv []string) error {
	listed, err := os.ReadFile(filepath.Join(home, "resolver"))
	if err != nil {
		return nil
	}
	i := slices.Index(argv, "--hostname")
	if i < 0 || i+1 >= len(argv) {
		return nil
	}
	host := argv[i+1]
	log, err := os.OpenFile(filepath.Join(home, "lookups"), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err == nil {
		_, _ = fmt.Fprintln(log, host)
		_ = log.Close()
	}
	if !slices.Contains(strings.Fields(string(listed)), host) {
		return fmt.Errorf("lookup %s: no such host", host)
	}
	return nil
}
