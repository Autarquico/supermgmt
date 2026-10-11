package backup_test

import (
	"testing"
	"time"

	"github.com/autarquico/supermgmt/internal/backup"
)

func at(s string) time.Time {
	t, err := time.Parse("2006-01-02 15:04", s)
	if err != nil {
		panic(err)
	}
	return t
}

func TestScheduleNext(t *testing.T) {
	tests := []struct {
		name, expr, after, want string
	}{
		{"daily default, before", "0 3 * * *", "2026-10-10 02:59", "2026-10-10 03:00"},
		{"daily default, at the minute is strictly after", "0 3 * * *", "2026-10-10 03:00", "2026-10-11 03:00"},
		{"every minute", "* * * * *", "2026-10-10 12:00", "2026-10-10 12:01"},
		{"every 15 minutes", "*/15 * * * *", "2026-10-10 12:16", "2026-10-10 12:30"},
		{"step over a range", "10-40/10 * * * *", "2026-10-10 12:41", "2026-10-10 13:10"},
		{"start with step", "5/20 * * * *", "2026-10-10 12:06", "2026-10-10 12:25"},
		{"list", "0 6,18 * * *", "2026-10-10 06:00", "2026-10-10 18:00"},
		{"rolls over the year", "0 0 1 1 *", "2026-10-10 12:00", "2027-01-01 00:00"},
		{"month names", "0 0 1 mar,jun *", "2026-04-01 00:00", "2026-06-01 00:00"},
		{"weekday number: 2026-10-10 is a Saturday", "30 8 * * 1", "2026-10-10 09:00", "2026-10-12 08:30"},
		{"weekday name", "30 8 * * MON-FRI", "2026-10-10 09:00", "2026-10-12 08:30"},
		{"7 is Sunday", "0 0 * * 7", "2026-10-10 12:00", "2026-10-11 00:00"},
		{"0 is Sunday", "0 0 * * 0", "2026-10-10 12:00", "2026-10-11 00:00"},
		{"both day fields restricted: either matches (day of month)", "0 0 13 * 5", "2026-10-10 12:00", "2026-10-13 00:00"},
		{"both day fields restricted: either matches (weekday)", "0 0 20 * 5", "2026-10-10 12:00", "2026-10-16 00:00"},
		{"star-step day-of-month counts as unrestricted: both must match", "0 0 */2 * 1", "2026-10-10 12:00", "2026-10-19 00:00"},
		{"leap day", "0 0 29 2 *", "2026-10-10 12:00", "2028-02-29 00:00"},
		{"end of month", "0 0 31 * *", "2026-11-01 00:00", "2026-12-31 00:00"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s, err := backup.ParseSchedule(tt.expr)
			if err != nil {
				t.Fatalf("ParseSchedule(%q): %v", tt.expr, err)
			}
			got := s.Next(at(tt.after))
			if !got.Equal(at(tt.want)) {
				t.Errorf("Next(%s) = %s, want %s", tt.after, got.Format("2006-01-02 15:04"), tt.want)
			}
		})
	}
}

func TestScheduleNextIgnoresSecondsWithinTheMinute(t *testing.T) {
	s, _ := backup.ParseSchedule("0 3 * * *")

	got := s.Next(at("2026-10-10 03:00").Add(30 * time.Second))

	if !got.Equal(at("2026-10-11 03:00")) {
		t.Errorf("Next = %s", got)
	}
}

func TestScheduleNextKeepsTheLocationOfItsInput(t *testing.T) {
	madrid, err := time.LoadLocation("Europe/Madrid")
	if err != nil {
		t.Skip("no tzdata")
	}
	s, _ := backup.ParseSchedule("0 3 * * *")

	got := s.Next(time.Date(2026, 10, 10, 4, 0, 0, 0, madrid))

	if want := time.Date(2026, 10, 11, 3, 0, 0, 0, madrid); !got.Equal(want) || got.Location() != madrid {
		t.Errorf("Next = %s, want %s", got, want)
	}
}

func TestScheduleThatCanNeverFireReturnsTheZeroTime(t *testing.T) {
	s, err := backup.ParseSchedule("0 0 31 2 *") // February 31st
	if err != nil {
		t.Fatal(err)
	}

	if got := s.Next(at("2026-01-01 00:00")); !got.IsZero() {
		t.Errorf("Next = %s, want the zero time", got)
	}
}

func TestParseScheduleRejects(t *testing.T) {
	for _, expr := range []string{
		"", "* * * *", "* * * * * *", "60 * * * *", "* 24 * * *", "* * 0 * *", "* * 32 * *", "* * * 0 *", "* * * 13 *",
		"* * * * 8", "-1 * * * *", "5-1 * * * *", "*/0 * * * *", "*/x * * * *", "a * * * *", "1,,2 * * * *", "1- * * * *",
		"@daily", "* * * foo *", "* * * * funday", "1/0 * * * *",
	} {
		if _, err := backup.ParseSchedule(expr); err == nil {
			t.Errorf("ParseSchedule(%q) succeeded", expr)
		}
	}
}
