package cli

import (
	"bytes"
	"strings"
	"testing"

	"github.com/autarquico/supermgmt/internal/api/wire"
)

func TestBareHashGetsTheSha256Prefix(t *testing.T) {
	bare := strings.Repeat("ab", 32)
	if got := withHashPrefix(bare); got != "sha256:"+bare {
		t.Errorf("bare digest: got %q", got)
	}
	if got := withHashPrefix("sha256:" + bare); got != "sha256:"+bare {
		t.Errorf("prefixed digest changed: %q", got)
	}
	if got := withHashPrefix("H"); got != "H" {
		t.Errorf("non-digest changed: %q", got)
	}
}

func TestApprovalsMarkStalePlans(t *testing.T) {
	page := wire.Page[wire.Approval]{Items: []wire.Approval{{Stale: true}, {}}}
	var out bytes.Buffer
	if err := writeApprovals(&out, page, false); err != nil {
		t.Fatal(err)
	}
	if n := strings.Count(out.String(), "STALE"); n != 1 {
		t.Errorf("want exactly one STALE mark, got %d in:\n%s", n, out.String())
	}
}
