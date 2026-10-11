package cli

import (
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/autarquico/supermgmt/internal/api/wire"
)

func TestSecretsKeysListsTheMasterKeysWithoutKeyMaterial(t *testing.T) {
	created := time.Date(2026, 10, 1, 8, 0, 0, 0, time.UTC)
	keys := []wire.MasterKey{
		{ID: "0192a000-0000-7000-8000-00000000f002", Active: true, Loaded: true, CreatedAt: created},
		{ID: "0192a000-0000-7000-8000-00000000f001", Loaded: false, CreatedAt: created.Add(-24 * time.Hour)},
	}
	f := newFakeAPI(t, router(map[string]http.HandlerFunc{
		"GET " + wire.PathMasterKeys: func(w http.ResponseWriter, _ *http.Request) { reply(w, 200, wire.Page[wire.MasterKey]{Items: keys}) },
	}))

	r := f.run("secrets", "keys")

	if r.code != 0 {
		t.Fatalf("exit %d: %s", r.code, r.stderr)
	}
	for _, want := range []string{"ACTIVE", "LOADED", "0192a000-0000-7000-8000-00000000f002", "yes     yes", "2026-10-01T08:00:00Z", "0192a000-0000-7000-8000-00000000f001", "no      no"} {
		if !strings.Contains(r.stdout, want) {
			t.Errorf("output lacks %q:\n%s", want, r.stdout)
		}
	}
	if m := f.Mutations(); len(m) != 0 {
		t.Errorf("listing sent mutations: %+v", m)
	}
}

func TestSecretsKeysJSONIsThePage(t *testing.T) {
	f := newFakeAPI(t, router(map[string]http.HandlerFunc{
		"GET " + wire.PathMasterKeys: func(w http.ResponseWriter, _ *http.Request) {
			reply(w, 200, wire.Page[wire.MasterKey]{Items: []wire.MasterKey{{ID: "0192a000-0000-7000-8000-00000000f001", Active: true}}})
		},
	}))

	r := f.run("secrets", "keys", "--json")

	var page wire.Page[wire.MasterKey]
	if err := json.Unmarshal([]byte(r.stdout), &page); err != nil || len(page.Items) != 1 || !page.Items[0].Active {
		t.Fatalf("stdout %q: %v", r.stdout, err)
	}
}

func TestOfflineExportLeavesNoWALOrSHMBehind(t *testing.T) {
	s, id := keyedSandbox(t)
	dbDir := filepath.Dir(s.dbPath)
	export := filepath.Join(t.TempDir(), "kek.smkey")

	exported := s.runIn(passphrase+"\n", "secrets", "export-key", string(id), "--offline", "--out", export)
	again := s.runIn(passphrase+"\n", "secrets", "export-key", string(id), "--offline", "--out", filepath.Join(t.TempDir(), "again.smkey"))

	if exported.code != 0 || again.code != 0 {
		t.Fatalf("export %d: %s; again %d: %s", exported.code, exported.stderr, again.code, again.stderr)
	}
	for _, name := range dirNames(t, dbDir) {
		if strings.HasSuffix(name, "-wal") || strings.HasSuffix(name, "-shm") {
			t.Errorf("%s was left next to the database", name)
		}
	}
}

func dirNames(t *testing.T, dir string) []string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, e := range entries {
		names = append(names, e.Name())
	}
	return names
}
