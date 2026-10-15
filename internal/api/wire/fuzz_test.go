package wire

import (
	"net/url"
	"strings"
	"testing"

	"github.com/autarquico/supermgmt/internal/domain"
	smerr "github.com/autarquico/supermgmt/internal/errors"
)

// FuzzParseQueries drives every query parser with one raw query string: each
// returns a value within its bounds or an invalid_argument error.
func FuzzParseQueries(f *testing.F) {
	f.Add("")
	f.Add("limit=10&cursor=abc")
	f.Add("limit=501")
	f.Add("limit=-1")
	f.Add("limit=99999999999999999999")
	f.Add("limit=0x10")
	f.Add("environment=prod&tag=db&reachability=reachable")
	f.Add("state=queued&state=running&state=bogus")
	f.Add("resource_type=node&resource_id=x&after_seq=5")
	f.Add("lines=10000")
	f.Add("lines=10001")
	f.Add("%zz=1&limit=%00")

	f.Fuzz(func(t *testing.T, raw string) {
		values, _ := url.ParseQuery(raw)

		page, err := ParsePageQuery(values)
		wantFuzzQueryOutcome(t, "page", err, page.Limit >= 0 && page.Limit <= MaxLimit)

		_, err = ParseNodeQuery(values)
		wantFuzzQueryOutcome(t, "node", err, true)
		_, err = ParseJobQuery(values)
		wantFuzzQueryOutcome(t, "job", err, true)
		_, err = ParseEventQuery(values)
		wantFuzzQueryOutcome(t, "event", err, true)

		logs, err := ParseLogQuery(values)
		wantFuzzQueryOutcome(t, "log", err, logs.Lines >= 0 && logs.Lines <= 10000)
	})
}

func wantFuzzQueryOutcome(t *testing.T, parser string, err error, inBounds bool) {
	t.Helper()
	if err != nil {
		if smerr.CodeOf(err) != smerr.CodeInvalidArgument {
			t.Fatalf("%s query: error %v is not invalid_argument", parser, err)
		}
		return
	}
	if !inBounds {
		t.Fatalf("%s query accepted an out-of-bounds value", parser)
	}
}

func FuzzParseUnitSpec(f *testing.F) {
	for _, seed := range []string{"nginx.service", "app.service:restart", "a.service:start,stop,start", ":restart", "a:reload", "a:", ""} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, spec string) {
		g, err := ParseUnitSpec(spec)
		if err != nil {
			return
		}
		if g.Unit == "" || strings.Contains(g.Unit, ":") || len(g.Verbs) == 0 {
			t.Fatalf("ParseUnitSpec(%q) = %+v", spec, g)
		}
		seen := map[domain.ServiceVerb]bool{}
		for _, v := range g.Verbs {
			if !v.Valid() || seen[v] {
				t.Fatalf("ParseUnitSpec(%q): verbs %v are not distinct valid verbs", spec, g.Verbs)
			}
			seen[v] = true
		}
	})
}
