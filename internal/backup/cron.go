package backup

import (
	"fmt"
	"strconv"
	"strings"
	"time"
)

// Schedule is a parsed 5-field cron expression: minute hour day-of-month
// month day-of-week. Fields accept "*", numbers, ranges "a-b", lists "a,b",
// steps "*/n" and "a-b/n", and the three-letter names of months and weekdays.
// Weekday 7 is Sunday. As in classic cron, when both day fields are
// restricted a time matches if either does.
type Schedule struct {
	minute, hour, dayOfMonth, month, dayOfWeek bitset
	dayOfMonthAny, dayOfWeekAny                bool
}

type bitset uint64

func (b bitset) has(n int) bool { return b&(1<<uint(n)) != 0 }

type fieldSpec struct {
	name     string
	min, max int
	names    []string // names[i] is the name of min+i
}

var (
	minuteField = fieldSpec{name: "minute", min: 0, max: 59}
	hourField   = fieldSpec{name: "hour", min: 0, max: 23}
	domField    = fieldSpec{name: "day of month", min: 1, max: 31}
	monthField  = fieldSpec{
		name: "month", min: 1, max: 12,
		names: []string{"jan", "feb", "mar", "apr", "may", "jun", "jul", "aug", "sep", "oct", "nov", "dec"},
	}
	dowField = fieldSpec{
		name: "day of week", min: 0, max: 7,
		names: []string{"sun", "mon", "tue", "wed", "thu", "fri", "sat"},
	}
)

// maxSearch bounds Next: a valid schedule fires at least every 8 years (the
// longest gap of "0 0 29 2 *" across a skipped leap year).
const maxSearch = 8

// ParseSchedule parses expr.
func ParseSchedule(expr string) (Schedule, error) {
	fields := strings.Fields(expr)
	if len(fields) != 5 {
		return Schedule{}, fmt.Errorf("cron expression %q must have 5 fields, has %d", expr, len(fields))
	}
	var s Schedule
	var err error
	if s.minute, _, err = parseField(fields[0], minuteField); err != nil {
		return Schedule{}, err
	}
	if s.hour, _, err = parseField(fields[1], hourField); err != nil {
		return Schedule{}, err
	}
	if s.dayOfMonth, s.dayOfMonthAny, err = parseField(fields[2], domField); err != nil {
		return Schedule{}, err
	}
	if s.month, _, err = parseField(fields[3], monthField); err != nil {
		return Schedule{}, err
	}
	if s.dayOfWeek, s.dayOfWeekAny, err = parseField(fields[4], dowField); err != nil {
		return Schedule{}, err
	}
	if s.dayOfWeek.has(7) {
		s.dayOfWeek |= 1 // 7 is Sunday
	}
	return s, nil
}

// parseField returns the set a field selects and whether it starts with "*" (cron treats "*/n" as unrestricted for the day rule).
func parseField(field string, spec fieldSpec) (bitset, bool, error) {
	var set bitset
	for part := range strings.SplitSeq(field, ",") {
		bits, err := parsePart(part, spec)
		if err != nil {
			return 0, false, fmt.Errorf("%s field %q: %w", spec.name, field, err)
		}
		set |= bits
	}
	return set, strings.HasPrefix(field, "*"), nil
}

func parsePart(part string, spec fieldSpec) (bitset, error) {
	rangeText, stepText, hasStep := strings.Cut(part, "/")
	step := 1
	if hasStep {
		n, err := strconv.Atoi(stepText)
		if err != nil || n < 1 {
			return 0, fmt.Errorf("step %q must be a positive number", stepText)
		}
		step = n
	}
	lo, hi, err := parseRange(rangeText, spec, hasStep)
	if err != nil {
		return 0, err
	}
	var set bitset
	for n := lo; n <= hi; n += step {
		set |= 1 << uint(n)
	}
	return set, nil
}

func parseRange(text string, spec fieldSpec, hasStep bool) (int, int, error) {
	if text == "*" {
		return spec.min, spec.max, nil
	}
	loText, hiText, isRange := strings.Cut(text, "-")
	lo, err := parseValue(loText, spec)
	if err != nil {
		return 0, 0, err
	}
	switch {
	case isRange:
		hi, err := parseValue(hiText, spec)
		if err != nil {
			return 0, 0, err
		}
		if hi < lo {
			return 0, 0, fmt.Errorf("range %q runs backwards", text)
		}
		return lo, hi, nil
	case hasStep:
		return lo, spec.max, nil // "5/10" means 5-max/10
	}
	return lo, lo, nil
}

func parseValue(text string, spec fieldSpec) (int, error) {
	for i, name := range spec.names {
		if strings.EqualFold(text, name) {
			return spec.min + i, nil
		}
	}
	n, err := strconv.Atoi(text)
	if err != nil {
		return 0, fmt.Errorf("%q is not a number or a name", text)
	}
	if n < spec.min || n > spec.max {
		return 0, fmt.Errorf("%d is outside %d-%d", n, spec.min, spec.max)
	}
	return n, nil
}

// Next returns the first scheduled minute strictly after t, in t's location,
// or the zero time if there is none.
func (s Schedule) Next(t time.Time) time.Time {
	t = t.Truncate(time.Minute).Add(time.Minute)
	limit := t.AddDate(maxSearch, 0, 0)
	for t.Before(limit) {
		switch {
		case !s.month.has(int(t.Month())):
			t = time.Date(t.Year(), t.Month()+1, 1, 0, 0, 0, 0, t.Location())
		case !s.matchesDay(t):
			t = time.Date(t.Year(), t.Month(), t.Day()+1, 0, 0, 0, 0, t.Location())
		case !s.hour.has(t.Hour()):
			t = time.Date(t.Year(), t.Month(), t.Day(), t.Hour()+1, 0, 0, 0, t.Location())
		case !s.minute.has(t.Minute()):
			t = t.Add(time.Minute)
		default:
			return t
		}
	}
	return time.Time{}
}

func (s Schedule) matchesDay(t time.Time) bool {
	inMonth := s.dayOfMonth.has(t.Day())
	inWeek := s.dayOfWeek.has(int(t.Weekday()))
	if !s.dayOfMonthAny && !s.dayOfWeekAny {
		return inMonth || inWeek
	}
	return inMonth && inWeek
}
