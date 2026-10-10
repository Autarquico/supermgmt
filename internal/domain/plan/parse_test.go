package plan

import (
	"errors"
	"testing"

	smerr "github.com/autarquico/supermgmt/internal/errors"
)

func TestParseValidatesSourceBytes(t *testing.T) {
	rejected := map[string]string{
		"lone high surrogate":         `{"version":3,"risk":"read","action":"\ud800"}`,
		"lone low surrogate":          `{"version":3,"risk":"read","action":"\udc00"}`,
		"surrogate then non-low":      `{"version":3,"risk":"read","action":"\ud800A"}`,
		"invalid UTF-8 in value":      "{\"version\":3,\"risk\":\"read\",\"action\":\"a\xffb\"}",
		"invalid UTF-8 in key":        "{\"version\":3,\"risk\":\"read\",\"parameters\":{\"k\xff\":1}}",
		"duplicate top-level key":     `{"version":3,"risk":"read","action":"a","action":"b"}`,
		"duplicate nested key":        `{"version":3,"risk":"read","content":{"commit_sha":"a","commit_sha":"b"}}`,
		"duplicate in parameters":     `{"version":3,"risk":"read","parameters":{"x":{"y":1,"y":2}}}`,
		"duplicate after unescape":    `{"version":3,"risk":"read","action":"a","action":"b"}`,
		"duplicate inside array item": `{"version":3,"risk":"read","targets":[{"type":"a","type":"b","id":"1"}]}`,
	}
	for name, in := range rejected {
		t.Run(name, func(t *testing.T) {
			_, err := Parse([]byte(in))
			if err == nil {
				t.Fatal("accepted")
			}
			if !errors.Is(err, smerr.New(smerr.CodeInvalidArgument, "", "")) {
				t.Fatalf("error %v is not INVALID_ARGUMENT", err)
			}
		})
	}
	t.Run("a literal U+FFFD is valid and kept", func(t *testing.T) {
		p, err := Parse([]byte("{\"version\":3,\"risk\":\"read\",\"action\":\"�\"}"))
		if err != nil || p.Action != "�" {
			t.Fatalf("got %+v, %v", p, err)
		}
	})
}
