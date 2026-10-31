package database

import (
	"database/sql"
	"fmt"
	"reflect"
	"testing"
)

// rowOf is a scanner over fuzzed column values: every text column holds text, every integer column
// holds number, and the nullable column is NULL unless null is set.
type rowOf struct {
	text   string
	number int64
	null   bool
}

func (r rowOf) Scan(dest ...any) error {
	for _, d := range dest {
		if n, ok := d.(*sql.NullString); ok {
			*n = sql.NullString{} // as database/sql leaves a NULL
			if r.null {
				*n = sql.NullString{String: r.text, Valid: true}
			}
			continue
		}
		v := reflect.ValueOf(d).Elem()
		switch v.Kind() {
		case reflect.String:
			v.SetString(r.text)
		case reflect.Int, reflect.Int64:
			v.SetInt(r.number)
		default:
			return fmt.Errorf("unexpected destination %T", d)
		}
	}
	return nil
}

func FuzzScanAppRoute(f *testing.F) {
	f.Add("shop.example.test", int64(1_700_000_000_000), true)
	f.Add("", int64(0), false)
	f.Add("\x00\xff", int64(-1), true)
	f.Add("failed", int64(1<<63-1), true)
	f.Fuzz(func(t *testing.T, text string, number int64, null bool) {
		r, err := scanAppRoute(rowOf{text: text, number: number, null: null})
		if err != nil {
			t.Fatalf("scanAppRoute: %v", err)
		}
		if got, want := string(r.HaltedPhase), map[bool]string{true: text, false: ""}[null]; got != want {
			t.Errorf("halted phase = %q, want %q", got, want)
		}
		if r.Hostname != text || r.Port != int(number) || r.TunnelGeneration != number {
			t.Errorf("columns not carried over: %+v", r)
		}
	})
}
