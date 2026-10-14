package api

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	smerr "github.com/autarquico/supermgmt/internal/errors"
)

type fuzzRequestBody struct {
	Name string   `json:"name"`
	Tags []string `json:"tags"`
}

// FuzzReadInput feeds arbitrary bodies through the route body limit and the
// strict decoder: an oversize body is refused before decode, and anything the
// decoder refuses is an invalid_argument error.
func FuzzReadInput(f *testing.F) {
	f.Add([]byte(`{"name":"web","tags":["a"]}`), uint16(1024))
	f.Add([]byte(`{"name":"web","unknown":1}`), uint16(1024))
	f.Add([]byte(`{"name":"web"}{"name":"again"}`), uint16(1024))
	f.Add([]byte(`{"name":"web"} trailing`), uint16(1024))
	f.Add([]byte(`   `), uint16(1024))
	f.Add([]byte(`{"name":"`+strings.Repeat("x", 4096)+`"}`), uint16(64))
	f.Add([]byte(`[1,2,3]`), uint16(0))

	f.Fuzz(func(t *testing.T, body []byte, limit uint16) {
		w := httptest.NewRecorder()
		r := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/x", bytes.NewReader(body))
		r.Body = http.MaxBytesReader(w, r.Body, int64(limit))

		in, err := readInput(r)
		if len(body) > int(limit) {
			if err == nil {
				t.Fatalf("a %d byte body passed a %d byte limit", len(body), limit)
			}
			wantFuzzInvalidArgument(t, err)
			return
		}
		if err != nil {
			t.Fatalf("a %d byte body within a %d byte limit was refused: %v", len(body), limit, err)
		}
		if !bytes.Equal(in.body, body) {
			t.Fatal("the stored body differs from the request body")
		}

		if _, err := decode[fuzzRequestBody](in); err != nil {
			wantFuzzInvalidArgument(t, err)
			return
		}
		if len(bytes.TrimSpace(body)) == 0 {
			t.Fatal("an empty body was decoded")
		}
	})
}

func wantFuzzInvalidArgument(t *testing.T, err error) {
	t.Helper()
	if smerr.CodeOf(err) != smerr.CodeInvalidArgument {
		t.Fatalf("error %v is not invalid_argument", err)
	}
}
