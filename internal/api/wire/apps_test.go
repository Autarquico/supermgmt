package wire

import (
	"net/url"
	"strings"
	"testing"

	smerr "github.com/autarquico/supermgmt/internal/errors"
)

func TestAppLogQueryRoundTripsAndRefusesWhatDoesNotCombine(t *testing.T) {
	q := AppLogQuery{Component: "web", Lines: 50, Cursor: "abc"}
	got, err := ParseAppLogQuery(q.Values())
	if err != nil || got != q {
		t.Fatalf("round trip = %+v, %v", got, err)
	}
	for name, v := range map[string]url.Values{
		"cursor and search": {"cursor": {"a"}, "search": {"b"}},
		"too many lines":    {"lines": {"1001"}},
		"negative lines":    {"lines": {"-1"}},
		"long term":         {"search": {strings.Repeat("x", MaxSearchTermBytes+1)}},
	} {
		if _, err := ParseAppLogQuery(v); smerr.CodeOf(err) != smerr.CodeInvalidArgument {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func TestAppsQueryReadsTrueFalseAndNothingElse(t *testing.T) {
	got, err := ParseAppsQuery(AppsQuery{Stats: true}.Values())
	if err != nil || !got.Stats || got.Errors {
		t.Errorf("query = %+v, %v", got, err)
	}
	if got, err := ParseAppsQuery(url.Values{"errors": {"false"}}); err != nil || got.Errors {
		t.Errorf("false = %+v, %v", got, err)
	}
	if _, err := ParseAppsQuery(url.Values{"stats": {"yes"}}); smerr.CodeOf(err) != smerr.CodeInvalidArgument {
		t.Errorf("yes: %v", err)
	}
}
