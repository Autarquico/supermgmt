package tunnel

import (
	"archive/tar"
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"slices"
	"strings"
	"sync"

	"github.com/klauspost/compress/zstd" //nolint:depguard // the scan has to read the archive it just made: only decompressing it shows what a backup holds (ADR-0020 keeps production readers in internal/backup)

	"github.com/autarquico/supermgmt/internal/backup"
	"github.com/autarquico/supermgmt/internal/database"
	"github.com/autarquico/supermgmt/internal/domain"
	"github.com/autarquico/supermgmt/internal/secrets"
	"github.com/autarquico/supermgmt/internal/transport"
	sshtransport "github.com/autarquico/supermgmt/internal/transport/ssh"
	"github.com/autarquico/supermgmt/internal/transport/ssh/templates"
)

// ---- what the control plane said and ran -----------------------------------

// transcript is an append-only text log shared by the stack's observers.
type transcript struct {
	mu   sync.Mutex
	text bytes.Buffer
}

func (l *transcript) add(parts ...string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.text.WriteString(strings.Join(parts, " "))
	l.text.WriteByte('\n')
}

func (l *transcript) bytes() []byte {
	l.mu.Lock()
	defer l.mu.Unlock()
	return slices.Clone(l.text.Bytes())
}

// recordingDialer wraps the SSH pool so every command the control plane runs on
// a node is recorded deterministically (its rendered line, its stdin unless the
// template is sensitive, and what came back), instead of sampling `ps`.
type recordingDialer struct {
	inner interface {
		For(t sshtransport.Target) transport.Executor
		State(node domain.ID) sshtransport.ConnState
		Invalidate(node domain.ID, user string)
	}
	log *transcript
}

func (d recordingDialer) For(t sshtransport.Target) transport.Executor {
	return recordingExecutor{inner: d.inner.For(t), log: d.log, who: t.User + "@" + string(t.Transport.Effective())}
}

func (d recordingDialer) State(node domain.ID) sshtransport.ConnState { return d.inner.State(node) }

func (d recordingDialer) Invalidate(node domain.ID, user string) { d.inner.Invalidate(node, user) }

// InvalidateNode keeps the pool's retire-everything behaviour visible to the
// connector, which looks for it with a type assertion.
func (d recordingDialer) InvalidateNode(node domain.ID) {
	if inv, ok := d.inner.(interface{ InvalidateNode(domain.ID) }); ok {
		inv.InvalidateNode(node)
	}
}

type recordingExecutor struct {
	inner transport.Executor
	log   *transcript
	who   string
}

func (e recordingExecutor) Run(ctx context.Context, c templates.Command) (transport.Result, error) {
	e.log.add("cmd", e.who, c.Template, c.Line)
	if !c.Sensitive && len(c.Stdin) > 0 {
		e.log.add("stdin", c.Template, string(c.Stdin))
	}
	res, err := e.inner.Run(ctx, c)
	e.log.add("out", c.Template, string(res.Stdout), string(res.Stderr))
	if err != nil {
		e.log.add("err", c.Template, err.Error())
	}
	return res, err
}

// ---- reading the stores -----------------------------------------------------

// dumpDatabase returns every table as text, blobs included: events, plans,
// jobs and their payloads, the operation records, the sealed secrets.
func (s *stack) dumpDatabase() map[string][]byte {
	s.t.Helper()
	ctx := context.Background()
	names, err := s.db.Reader().QueryContext(ctx, `SELECT name FROM sqlite_master WHERE type = 'table' ORDER BY name`)
	must(s.t, err)
	var tables []string
	for names.Next() {
		var n string
		must(s.t, names.Scan(&n))
		tables = append(tables, n)
	}
	must(s.t, names.Err())
	must(s.t, names.Close())

	out := make(map[string][]byte, len(tables))
	for _, table := range tables {
		rows, err := s.db.Reader().QueryContext(ctx, `SELECT * FROM "`+table+`"`)
		must(s.t, err)
		cols, err := rows.Columns()
		must(s.t, err)
		var buf bytes.Buffer
		for rows.Next() {
			vals := make([]any, len(cols))
			ptrs := make([]any, len(cols))
			for i := range vals {
				ptrs[i] = &vals[i]
			}
			must(s.t, rows.Scan(ptrs...))
			for _, v := range vals {
				switch x := v.(type) {
				case []byte:
					buf.Write(x)
				case nil:
				default:
					fmt.Fprint(&buf, x)
				}
				buf.WriteByte('|')
			}
			buf.WriteByte('\n')
		}
		must(s.t, rows.Err())
		must(s.t, rows.Close())
		out["db:"+table] = buf.Bytes()
	}
	return out
}

// archive creates a backup and returns every member, decompressed.
func (s *stack) archive() map[string][]byte {
	s.t.Helper()
	ctx := context.Background()
	must(s.t, s.db.WithWriteTx(ctx, func(ctx context.Context, tx *database.Tx) error {
		_, err := database.PutConfigSnapshot(ctx, tx, []byte("version: 1\n"), nil, s.clock.Now())
		return err
	}))
	created, err := backup.Create(ctx, backup.CreateOptions{
		Dir: s.dir + "/backups", Instance: instanceName, SMVersion: "0.0.0-test", Clock: s.clock, Source: s.db, Keys: s.keys,
	})
	must(s.t, err)
	f, err := os.Open(created.Path)
	must(s.t, err)
	defer f.Close()
	zr, err := zstd.NewReader(f)
	must(s.t, err)
	defer zr.Close()
	members := map[string][]byte{}
	tr := tar.NewReader(zr)
	for {
		h, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		must(s.t, err)
		data, err := io.ReadAll(tr)
		must(s.t, err)
		members["backup:"+h.Name] = data
	}
	// The database copy is the archive's interesting member: dump it as text too.
	if db, ok := members["backup:"+backup.DatabaseName]; ok {
		members["backup-db-text"] = db
	}
	return members
}

// ---- the credentials under test ----------------------------------------------

// credentials are the three secrets the feature handles, by name. The values
// are read from where they live, never invented, so a scan that finds nothing
// is not vacuous.
type credentials map[string]string

func (c credentials) add(name, value string) {
	if value != "" {
		c[name] = value
	}
}

func (c credentials) has(value string) bool {
	for _, v := range c {
		if v == value {
			return true
		}
	}
	return false
}

// serviceTokenSecret is the secret half of the stored runtime service token.
func (s *stack) serviceTokenSecret() string {
	s.t.Helper()
	stored, err := s.store.Get(context.Background(), secrets.Ref{Name: "cloudflare/access-service-token"})
	if err != nil {
		return ""
	}
	_, secret, _ := strings.Cut(stored.Reveal(), ":")
	return secret
}

// tunnelTokens returns, for every live tunnel, the run token and its secret
// component.
func (s *stack) tunnelTokens() map[string]string {
	s.t.Helper()
	client, err := s.newCloudflareClient()
	must(s.t, err)
	out := map[string]string{}
	for _, tun := range s.cf.Tunnels() {
		token, err := client.TunnelToken(context.Background(), tun.ID)
		must(s.t, err)
		out["tunnel token "+tun.ID] = token.Reveal()
		if raw, err := base64.StdEncoding.DecodeString(token.Reveal()); err == nil {
			var doc map[string]string
			if json.Unmarshal(raw, &doc) == nil {
				out["tunnel secret "+tun.ID] = doc["s"]
			}
		}
	}
	return out
}

// collect gathers every credential that exists now into c.
func (s *stack) collect(c credentials) {
	s.t.Helper()
	c.add("API token", seededAPIToken)
	if stored := s.serviceTokenSecret(); stored != "" && !c.has(stored) {
		c.add(fmt.Sprintf("stored service token secret #%d", len(c)), stored)
	}
	for name, value := range s.tunnelTokens() {
		c.add(name, value)
	}
	for _, tok := range s.cf.ServiceTokens() {
		if !c.has(tok.ClientSecret) {
			c.add("service token secret of "+tok.ID, tok.ClientSecret)
		}
	}
}

// leaks lists "<credential> in <place>" for every haystack that contains a
// credential. It never prints a value.
func leaks(creds credentials, places map[string][]byte) []string {
	var found []string
	for place, data := range places {
		for name, value := range creds {
			if bytes.Contains(data, []byte(value)) {
				found = append(found, name+" in "+place)
			}
		}
	}
	slices.Sort(found)
	return found
}
