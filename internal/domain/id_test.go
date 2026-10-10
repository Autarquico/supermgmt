package domain_test

import (
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/autarquico/supermgmt/internal/domain"
	"github.com/autarquico/supermgmt/internal/domain/domaintest"
	smerr "github.com/autarquico/supermgmt/internal/errors"
)

func TestUUIDv7GeneratorIssuesParsableUniqueIDs(t *testing.T) {
	var g domain.UUIDv7Generator
	seen := map[domain.ID]bool{}
	for range 100 {
		id := g.NewID()
		if _, err := domain.ParseID(string(id)); err != nil {
			t.Fatalf("generated id %q does not parse: %v", id, err)
		}
		if seen[id] {
			t.Fatalf("duplicate id %q", id)
		}
		seen[id] = true
	}
}

func TestParseID(t *testing.T) {
	valid := uuid.Must(uuid.NewV7()).String()
	tests := []struct {
		name string
		in   string
		ok   bool
	}{
		{"canonical v7", valid, true},
		{"uppercase", strings.ToUpper(valid), false},
		{"v4", uuid.New().String(), false},
		{"empty", "", false},
		{"malformed", "not-a-uuid", false},
		{"urn form", "urn:uuid:" + valid, false},
		{"braced", "{" + valid + "}", false},
		{"no hyphens", strings.ReplaceAll(valid, "-", ""), false},
		{"non-rfc4122 variant", valid[:19] + "c" + valid[20:], false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			id, err := domain.ParseID(tt.in)
			if tt.ok {
				if err != nil || string(id) != tt.in {
					t.Fatalf("ParseID(%q) = %q, %v", tt.in, id, err)
				}
				return
			}
			if err == nil {
				t.Fatalf("ParseID(%q) accepted", tt.in)
			}
			if smerr.CodeOf(err) != smerr.CodeInvalidArgument {
				t.Errorf("code = %s, want INVALID_ARGUMENT", smerr.CodeOf(err))
			}
		})
	}
}

func TestSequentialIDsAreValidDeterministicAndOrdered(t *testing.T) {
	a, b := domaintest.NewSequentialIDs(), domaintest.NewSequentialIDs()
	var prev domain.ID
	for i := range 70000 { // crosses the 16-bit boundary of the counter
		id := a.NewID()
		if id != b.NewID() {
			t.Fatalf("generators diverged at %d", i)
		}
		if _, err := domain.ParseID(string(id)); err != nil {
			t.Fatalf("id %q at %d is not a valid v7: %v", id, i, err)
		}
		if id <= prev {
			t.Fatalf("id %q at %d does not sort after %q", id, i, prev)
		}
		prev = id
	}
}

func TestSequentialIDsAreGoroutineSafe(t *testing.T) {
	g := domaintest.NewSequentialIDs()
	var mu sync.Mutex
	seen := map[domain.ID]bool{}
	var wg sync.WaitGroup
	for range 8 {
		wg.Go(func() {
			for range 100 {
				id := g.NewID()
				mu.Lock()
				if seen[id] {
					t.Errorf("duplicate id %q", id)
				}
				seen[id] = true
				mu.Unlock()
			}
		})
	}
	wg.Wait()
}

func TestUnixMillisRoundTrip(t *testing.T) {
	at := time.Date(2026, 1, 1, 12, 0, 0, 123_000_000, time.FixedZone("x", 3600))
	got := domain.FromUnixMillis(domain.UnixMillis(at))
	if !got.Equal(at) {
		t.Errorf("round trip = %v, want %v", got, at)
	}
	if got.Location() != time.UTC {
		t.Errorf("location = %v, want UTC", got.Location())
	}
}

func TestSystemClockReturnsUTCNow(t *testing.T) {
	before := time.Now()
	got := domain.SystemClock{}.Now()
	if got.Location() != time.UTC || got.Before(before) || time.Since(got) > time.Minute {
		t.Errorf("SystemClock.Now() = %v", got)
	}
}

func TestFakeClock(t *testing.T) {
	start := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	c := domaintest.NewFakeClock(start)
	var _ domain.Clock = c
	if !c.Now().Equal(start) {
		t.Fatalf("Now = %v, want %v", c.Now(), start)
	}
	c.Advance(90 * time.Second)
	if want := start.Add(90 * time.Second); !c.Now().Equal(want) {
		t.Errorf("after Advance Now = %v, want %v", c.Now(), want)
	}
	reset := start.Add(-time.Hour)
	c.Set(reset)
	if !c.Now().Equal(reset) {
		t.Errorf("after Set Now = %v, want %v", c.Now(), reset)
	}
}

func TestFakeClockIsGoroutineSafe(t *testing.T) {
	c := domaintest.NewFakeClock(time.Unix(0, 0))
	var wg sync.WaitGroup
	for range 8 {
		wg.Go(func() {
			for range 100 {
				c.Advance(time.Second)
				_ = c.Now()
			}
		})
	}
	wg.Wait()
	if got := c.Now().Unix(); got != 800 {
		t.Errorf("Now = %d, want 800", got)
	}
}
