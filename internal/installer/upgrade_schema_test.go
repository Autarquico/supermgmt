package installer

import (
	"context"
	"strings"
	"testing"
)

// doctorStub answers every command with a fixed doctor report.
type doctorStub string

func (d doctorStub) Run(context.Context, Command) ([]byte, error) { return []byte(d), nil }

func TestUpgrade_SchemaVersionReaders(t *testing.T) {
	tests := []struct {
		name, doctor string
		want         int
		wantErr      string
	}{
		{"json field preferred over the text", `{"ok":true,"format_version":1,"database_schema_version":5,"binary_schema_version":6,"checks":[{"name":"schema","status":"ok","detail":"version 2 matches this binary"}]}`, 5, ""},
		{"json field null", `{"ok":false,"format_version":1,"database_schema_version":null,"binary_schema_version":6,"checks":[]}`, 0, "no database schema version"},
		{"M3 text: matches", `{"ok":true,"checks":[{"name":"schema","status":"ok","detail":"version 3 matches this binary"}]}`, 3, ""},
		{"M3 text: behind", `{"ok":true,"checks":[{"name":"schema","status":"warn","detail":"database schema version 3 is behind this binary (4); the daemon migrates on start"}]}`, 3, ""},
		{"M3 text: unreadable", `{"ok":false,"checks":[{"name":"schema","status":"fail","detail":"database schema version 9 is newer than this binary (4)"}]}`, 0, "reports the schema as fail"},
		{"no schema check", `{"ok":true,"checks":[]}`, 0, "no schema check"},
		{"no report", `not json`, 0, "no report"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			u := &upgrader{d: Deps{Runner: doctorStub(tc.doctor)}, t: upgradeTarget{l: applianceLayout()}}
			got, err := u.schemaVersion(context.Background(), applianceLayout().Binary)
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("err = %v, want %q", err, tc.wantErr)
				}
				return
			}
			if err != nil || got != tc.want {
				t.Fatalf("got %d, %v; want %d", got, err, tc.want)
			}
		})
	}
}

func TestUpgrade_LegacyDoctorBinaryStillUpgrades(t *testing.T) {
	h := newUHost(t)
	h.oldContent = binV1 + ";doctor=legacy"
	h.put(applianceLayout().Binary, h.oldContent)
	if err := h.upgrade(defaultHooks()); err != nil {
		t.Fatalf("%v\n%s", err, h.out.String())
	}
	if st, _ := h.state(); st.Phase != upDone || st.SchemaBefore != 3 {
		t.Errorf("state = %+v", st)
	}
	h.noViolations(t)
}
