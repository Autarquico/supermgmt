package api

import (
	"bytes"
	"errors"
	"log/slog"
	"net/http/httptest"
	"strings"
	"testing"

	smerr "github.com/autarquico/supermgmt/internal/errors"
)

func TestWriteErrorLogsWhatTheCallerCannotSee(t *testing.T) {
	cause := errors.New("dial tcp 192.0.2.1:22: connect: no route to host")
	for name, tc := range map[string]struct {
		err    error
		logged bool
	}{
		"unreachable node": {smerr.Wrap(cause, smerr.CodeNodeUnreachable, "", "scan host key"), true},
		"internal":         {smerr.Wrap(cause, smerr.CodeInternal, "", "boom"), true},
		"caller's mistake": {smerr.New(smerr.CodeInvalidArgument, "", "bad host"), false},
	} {
		t.Run(name, func(t *testing.T) {
			var logs bytes.Buffer
			r := responder{log: slog.New(slog.NewTextHandler(&logs, nil))}

			r.writeError(httptest.NewRecorder(), httptest.NewRequestWithContext(t.Context(), "POST", "/api/v1/nodes", nil), tc.err)

			if got := strings.Contains(logs.String(), "no route to host"); got != tc.logged {
				t.Errorf("cause logged = %v, want %v: %q", got, tc.logged, logs.String())
			}
		})
	}
}
