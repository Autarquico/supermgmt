package database

import (
	"encoding/json"
	"testing"

	"github.com/autarquico/supermgmt/internal/domain"
)

func FuzzScanAppMove(f *testing.F) {
	f.Add("move-1", int64(1_700_000_000_000), true)
	f.Add("", int64(0), false)
	f.Add("\x00\xff", int64(-1), true)
	f.Add("failed", int64(1<<63-1), true)
	f.Fuzz(func(t *testing.T, text string, number int64, null bool) {
		m, err := scanAppMove(rowOf{text: text, number: number, null: null})
		if err != nil {
			t.Fatalf("scanAppMove: %v", err)
		}
		if got, want := string(m.HaltedPhase), map[bool]string{true: text, false: ""}[null]; got != want {
			t.Errorf("halted phase = %q, want %q", got, want)
		}
		if (m.DestDeploymentID != nil) != null || (m.BStartedAt != nil) != (number != 0) {
			t.Errorf("optional columns: dest %v, started %v", m.DestDeploymentID, m.BStartedAt)
		}
		if m.ID.String() != text || m.CommittedRevision != number || m.Stateful != (number == 1) {
			t.Errorf("columns not carried over: %+v", m)
		}
	})
}

func FuzzScanAppMoveVolume(f *testing.F) {
	f.Add(`["worker"]`, int64(1_700_000_000_000))
	f.Add(`[]`, int64(0))
	f.Add(`not json`, int64(-1))
	f.Add("\x00\xff", int64(1<<63-1))
	f.Fuzz(func(t *testing.T, text string, number int64) {
		v, err := scanAppMoveVolume(rowOf{text: text, number: number})
		var decoded []string
		if valid := json.Unmarshal([]byte(text), &decoded) == nil; valid != (err == nil) {
			t.Fatalf("other services %q: err = %v", text, err)
		}
		if err != nil {
			return
		}
		if v.VolumeName != text || v.SourceBytes != number || (v.ImportDeadlineAt != nil) != (number != 0) || v.CreatedByMove != (number == 1) {
			t.Errorf("columns not carried over: %+v", v)
		}
	})
}

func FuzzScanAppMoveRoute(f *testing.F) {
	f.Add("route-1", int64(1_700_000_000_000))
	f.Add("", int64(0))
	f.Add("\x00\xff", int64(-1))
	f.Add("dns_switched", int64(1<<63-1))
	f.Fuzz(func(t *testing.T, text string, number int64) {
		r, err := scanAppMoveRoute(rowOf{text: text, number: number})
		if err != nil {
			t.Fatalf("scanAppMoveRoute: %v", err)
		}
		if r.RouteID.String() != text || string(r.State) != text || r.FromGeneration != number || r.ToGeneration != number {
			t.Errorf("columns not carried over: %+v", r)
		}
		if !r.CreatedAt.Equal(domain.FromUnixMillis(number)) || !r.UpdatedAt.Equal(domain.FromUnixMillis(number)) {
			t.Errorf("timestamps: %v, %v", r.CreatedAt, r.UpdatedAt)
		}
	})
}
