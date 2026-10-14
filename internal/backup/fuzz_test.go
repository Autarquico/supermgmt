package backup

import (
	"archive/tar"
	"bytes"
	"context"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/klauspost/compress/zstd"
)

var archiveFuzzLimits = limits{database: 4 << 10, member: 1 << 10, total: 8 << 10}

const archiveFuzzSchemaMax = 100

func archiveFuzzManifest() Manifest {
	return Manifest{
		FormatVersion: FormatVersion, SMVersion: "v0.0.0", SchemaVersion: 1,
		CreatedAt: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC), ConfigGeneration: 1,
	}
}

func archiveFuzzValid(t testing.TB, members ...Member) []byte {
	t.Helper()
	var buf bytes.Buffer
	w, err := NewWriter(&buf)
	if err != nil {
		t.Fatal(err)
	}
	if err := w.WriteArchive(archiveFuzzManifest(), members); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// archiveFuzzWithTrailer is a valid archive followed, inside the same zstd
// stream, by zeros: a decompression bomb hiding after the tar footer.
func archiveFuzzWithTrailer(t testing.TB, trailer int) []byte {
	t.Helper()
	manifest := archiveFuzzManifest()
	manifest.SHA256 = map[string]string{DatabaseName: strings.Repeat("0", 64)}
	encoded, err := EncodeManifest(manifest)
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	zw, err := zstd.NewWriter(&buf)
	if err != nil {
		t.Fatal(err)
	}
	tw := tar.NewWriter(zw)
	if err := tw.WriteHeader(&tar.Header{Typeflag: tar.TypeReg, Name: ManifestName, Mode: 0o600, Size: int64(len(encoded))}); err != nil {
		t.Fatal(err)
	}
	if _, err := tw.Write(encoded); err != nil {
		t.Fatal(err)
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := zw.Write(make([]byte, trailer)); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func archiveFuzzExtract(t testing.TB, data []byte) (staged, string, error) {
	t.Helper()
	staging := t.TempDir()
	e := env{limits: archiveFuzzLimits}
	members, err := e.extract(context.Background(), bytes.NewReader(data), staging, archiveFuzzSchemaMax)
	return members, staging, err
}

func TestArchiveBombsAreRejectedWithinLimits(t *testing.T) {
	tests := []struct {
		name string
		data []byte
		want string
	}{
		{"member over its cap", archiveFuzzValid(t, BytesMember(DatabaseName, make([]byte, 2<<10)), BytesMember(ConfigName, make([]byte, 2<<10))), "limit"},
		{"zeros after the tar footer", archiveFuzzWithTrailer(t, 4<<20), "size budget"},
		{"garbage instead of zstd", bytes.Repeat([]byte{0xff}, 64), ""},
		{"empty stream", nil, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, staging, err := archiveFuzzExtract(t, tt.data)
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("extract error = %v, want one containing %q", err, tt.want)
			}
			assertStagedWithinLimits(t, staging)
		})
	}
}

func assertStagedWithinLimits(t testing.TB, staging string) {
	t.Helper()
	var total int64
	err := filepath.WalkDir(staging, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		info, err := d.Info()
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(staging, path)
		if info.Size() > archiveFuzzLimits.capOf(filepath.ToSlash(rel)) {
			t.Fatalf("staged %s has %d bytes, over its cap", rel, info.Size())
		}
		total += info.Size()
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if total > archiveFuzzLimits.total {
		t.Fatalf("staged %d bytes, over the %d byte total", total, archiveFuzzLimits.total)
	}
}

func FuzzReadArchive(f *testing.F) {
	valid := archiveFuzzValid(f, BytesMember(DatabaseName, []byte("db")), BytesMember(ConfigName, []byte("version: 1\n")))
	f.Add(valid)
	f.Add(valid[:len(valid)/2])
	f.Add(archiveFuzzValid(f, BytesMember(DatabaseName, make([]byte, 2<<10))))
	f.Add(archiveFuzzWithTrailer(f, 4<<20))
	f.Add([]byte{})
	f.Add([]byte("not zstd"))
	f.Fuzz(func(t *testing.T, data []byte) {
		members, staging, err := archiveFuzzExtract(t, data)
		assertStagedWithinLimits(t, staging)
		manifest, manifestErr := ReadManifest(bytes.NewReader(data))
		if err != nil {
			return
		}
		if manifestErr != nil {
			t.Fatalf("extract accepted an archive whose manifest ReadManifest rejects: %v", manifestErr)
		}
		if manifest.SchemaVersion != members.manifest.SchemaVersion {
			t.Fatalf("manifest schema differs between readers: %d and %d", manifest.SchemaVersion, members.manifest.SchemaVersion)
		}
		for name := range members.members {
			if _, listed := manifest.SHA256[name]; !listed {
				t.Fatalf("extracted %q, which the manifest does not list", name)
			}
		}
	})
}

func FuzzParseManifest(f *testing.F) {
	valid, err := EncodeManifest(func() Manifest {
		m := archiveFuzzManifest()
		m.SHA256 = map[string]string{DatabaseName: strings.Repeat("a", 64)}
		return m
	}())
	if err != nil {
		f.Fatal(err)
	}
	f.Add(valid)
	f.Add(valid[:len(valid)/2])
	for _, seed := range []string{
		"", "{}", "null", "[]", `{"format_version":1}`, `{"format_version":2}`, `{"bogus":1}`,
		`{"format_version":1,"schema_version":1,"created_at":"2026-01-01T00:00:00Z","config_generation":1,"sha256":{"manifest.json":"00"}}`,
		`{"format_version":1,"kek_ids":["x"]}`, "\xff\xfe",
	} {
		f.Add([]byte(seed))
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		m, err := ParseManifest(data)
		if err != nil {
			return
		}
		if err := validateManifest(m); err != nil {
			t.Fatalf("a manifest ParseManifest accepted fails validation: %v", err)
		}
		if _, err := EncodeManifest(m); err != nil {
			t.Fatalf("an accepted manifest cannot be encoded: %v", err)
		}
	})
}

func FuzzParseSchedule(f *testing.F) {
	for _, seed := range []string{
		"", "* * * * *", "0 3 * * *", "*/15 0-6 1,15 jan-mar mon-fri", "0 0 29 2 *", "5/10 * * * 7", "0 0 31 4 *",
		"60 * * * *", "* * * * * *", "-1 * * * *", "1-0 * * * *", "*/0 * * * *", "a b c d e", "\xff * * * *", "0 0 0 0 0",
	} {
		f.Add(seed)
	}
	from := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	f.Fuzz(func(t *testing.T, expr string) {
		s, err := ParseSchedule(expr)
		if err != nil {
			return
		}
		next := s.Next(from)
		if !next.IsZero() && !next.After(from) {
			t.Fatalf("%q: next %v is not after %v", expr, next, from)
		}
	})
}

func FuzzReadJournal(f *testing.F) {
	dataDir := f.TempDir()
	staging := filepath.Join(dataDir, stagingPrefix+"1")
	valid := `{"id":"j1","state":"staged","staging":` + quoteJSON(staging) + `,"moves":[` +
		`{"kind":"retire","from":"a","to":"b","status":"done"},{"kind":"install","from":"c","to":"d","status":"planned"}]}`
	for _, seed := range []string{
		valid, valid[:len(valid)/2], valid + "x", "", "{}", "null", `{"id":"j1","state":"complete","staging":"/etc","moves":[]}`,
		`{"id":"j1","state":"staged","staging":` + quoteJSON(staging) + `,"moves":[{"kind":"retire","from":"a","to":"b","status":"planned"},{"kind":"retire","from":"a","to":"b","status":"done"}]}`,
		`{"bogus":1}`, "\x00\x00\x00",
	} {
		f.Add([]byte(seed))
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		if err := os.WriteFile(journalPath(dataDir), data, 0o600); err != nil {
			t.Fatal(err)
		}
		j, found, err := readJournal(dataDir)
		if !found {
			t.Fatalf("a journal file exists but readJournal reports none (err %v)", err)
		}
		if err == nil {
			if err := j.validate(dataDir); err != nil {
				t.Fatalf("a journal readJournal accepted fails validation: %v", err)
			}
			return
		}
		var torn *tornJournalError
		if !errors.As(err, &torn) {
			t.Fatalf("an unreadable journal must be a *tornJournalError, got %T: %v", err, err)
		}
	})
}

func quoteJSON(s string) string { return `"` + strings.ReplaceAll(s, `\`, `\\`) + `"` }

func TestTornJournalTailIsRefusedNotGuessed(t *testing.T) {
	dir := t.TempDir()
	torn := `{"id":"j1","state":"staged","staging":"` + filepath.Join(dir, stagingPrefix+"1") + `","moves":[{"kind":"ret`
	if err := os.WriteFile(journalPath(dir), []byte(torn), 0o600); err != nil {
		t.Fatal(err)
	}
	_, found, err := readJournal(dir)
	var tornErr *tornJournalError
	if !found || !errors.As(err, &tornErr) {
		t.Fatalf("found=%v err=%v, want a found journal with a *tornJournalError", found, err)
	}
}
