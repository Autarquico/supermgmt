//go:build e2e

package harness

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"sort"
	"testing"
)

// Evidence is everything a secret could leak into on a server: the database and its write-ahead
// log (copied while the service runs) and the service journal.
func (s *Server) Evidence(ctx context.Context) map[string][]byte {
	s.t.Helper()
	out := map[string][]byte{}
	dir := s.t.TempDir()
	for _, name := range []string{"supermgmt.db", "supermgmt.db-wal"} {
		dst := filepath.Join(dir, name)
		res, err := Docker(ctx, "", "cp", s.C.Name+":"+ServerData+"/"+name, dst)
		if err != nil || res.Code != 0 {
			continue // no write-ahead log right after a checkpoint
		}
		raw, err := os.ReadFile(dst)
		if err != nil {
			s.t.Fatal(err)
		}
		out["database file "+name] = raw
	}
	journal := s.C.Exec(ctx, "", "journalctl", "-u", "supermgmt", "--no-pager", "-o", "cat")
	out["service journal"] = []byte(journal.Stdout)
	return out
}

// ArchiveEvidence unpacks a backup archive (.tar.zst) inside the container that holds it and returns
// the member names and the concatenated content of all members.
func (c *Container) ArchiveEvidence(ctx context.Context, path string) (names string, content []byte) {
	c.t.Helper()
	list := c.Exec(ctx, "", "tar", "--zstd", "-tf", path)
	data := c.Exec(ctx, "", "tar", "--zstd", "-xOf", path)
	if list.Code != 0 || data.Code != 0 {
		c.t.Fatalf("read archive %s: %s %s", path, list.Output(), data.Stderr)
	}
	return list.Stdout, []byte(data.Stdout)
}

// AssertNoPlaintext fails the test for each secret (by label, never by value) found in any evidence.
func AssertNoPlaintext(t testing.TB, evidence map[string][]byte, secrets map[string]string) {
	t.Helper()
	places := make([]string, 0, len(evidence))
	for place := range evidence {
		places = append(places, place)
	}
	sort.Strings(places)
	for _, place := range places {
		for label, value := range secrets {
			if value != "" && bytes.Contains(evidence[place], []byte(value)) {
				t.Errorf("%s appears in plaintext in the %s", label, place)
			}
		}
	}
}
