package mcp

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"testing"
	"unicode/utf8"
)

type injectionCase struct {
	Name      string   `json:"name"`
	Input     string   `json:"input"`
	Want      *string  `json:"want"`
	Forbidden []string `json:"forbidden"`
}

func injectionCorpus(t *testing.T) []injectionCase {
	t.Helper()
	raw, err := os.ReadFile("testdata/injection_corpus.json")
	if err != nil {
		t.Fatal(err)
	}
	var cases []injectionCase
	if err := json.Unmarshal(raw, &cases); err != nil {
		t.Fatal(err)
	}
	if len(cases) == 0 {
		t.Fatal("empty corpus")
	}
	return cases
}

func TestUntrustedText_InjectionCorpus(t *testing.T) {
	for _, tc := range injectionCorpus(t) {
		t.Run(tc.Name, func(t *testing.T) {
			got := untrustedText(tc.Input)
			if !got.Untrusted {
				t.Error("envelope is not flagged untrusted_remote_output")
			}
			if tc.Want != nil && got.Text != *tc.Want {
				t.Errorf("text = %q, want %q", got.Text, *tc.Want)
			}
			for _, bad := range tc.Forbidden {
				if strings.Contains(got.Text, bad) {
					t.Errorf("text %q still contains %q", got.Text, bad)
				}
			}
			wantEnvelopeSurvivesJSON(t, got)
		})
	}
}

// wantEnvelopeSurvivesJSON checks that hostile text cannot break out of its
// envelope: the serialized form has exactly the three envelope keys, with the
// flag set.
func wantEnvelopeSurvivesJSON(t *testing.T, u Untrusted) {
	t.Helper()
	raw, err := json.Marshal(u)
	if err != nil {
		t.Fatal(err)
	}
	var generic map[string]any
	if err := json.Unmarshal(raw, &generic); err != nil {
		t.Fatalf("envelope is not valid JSON: %v", err)
	}
	if len(generic) != 3 || generic["untrusted_remote_output"] != true {
		t.Errorf("envelope broke out: %s", raw)
	}
}

func TestUntrustedText_OneMiBIsCappedAndFlagged(t *testing.T) {
	got := untrustedText(strings.Repeat("0123456789abcdef", 1<<16)) // 1 MiB, one line
	if len(got.Text) > MaxUntrustedBytes {
		t.Errorf("text is %d bytes, cap is %d", len(got.Text), MaxUntrustedBytes)
	}
	if !got.Truncated {
		t.Error("a cut text must be flagged truncated")
	}
}

func TestUntrustedText_LineCap(t *testing.T) {
	lines := func(n int) string {
		parts := make([]string, n)
		for i := range parts {
			parts[i] = fmt.Sprintf("line %d", i)
		}
		return strings.Join(parts, "\n")
	}
	tests := []struct {
		name          string
		in            string
		wantLines     int
		wantTruncated bool
	}{
		{"under the cap", lines(MaxUntrustedLines - 1), MaxUntrustedLines - 1, false},
		{"at the cap", lines(MaxUntrustedLines), MaxUntrustedLines, false},
		{"at the cap with trailing newline", lines(MaxUntrustedLines) + "\n", MaxUntrustedLines, false},
		{"over the cap", lines(MaxUntrustedLines + 1), MaxUntrustedLines, true},
		{"far over the cap", lines(5000), MaxUntrustedLines, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := untrustedText(tt.in)
			if n := len(strings.Split(strings.TrimSuffix(got.Text, "\n"), "\n")); n != tt.wantLines {
				t.Errorf("lines = %d, want %d", n, tt.wantLines)
			}
			if got.Truncated != tt.wantTruncated {
				t.Errorf("truncated = %v, want %v", got.Truncated, tt.wantTruncated)
			}
		})
	}
}

func TestUntrustedText_CutsOnARuneBoundary(t *testing.T) {
	got := untrustedText(strings.Repeat("é", MaxUntrustedBytes)) // 2 bytes per rune
	if !utf8.ValidString(got.Text) {
		t.Error("cut split a rune")
	}
}

func TestUntrustedText_ACredentialIsNotSplitByTheCap(t *testing.T) {
	padding := strings.Repeat("x", MaxUntrustedBytes-10)
	got := untrustedText(padding + " password=hunter2-extremely-long")
	if strings.Contains(got.Text, "hunter") {
		t.Errorf("credential prefix leaked at the cut: %q", got.Text[len(got.Text)-30:])
	}
}

func TestUntrustedText_UnknownSecretUnderAHarmlessNameIsNotScrubbed(t *testing.T) {
	// The documented boundary of the redaction guarantee (ADR-0031).
	in := "DB_URL=postgres://app:hunter2@db/main"
	if got := untrustedText(in); got.Text != in {
		t.Errorf("text = %q; this limit is documented, not silently changed", got.Text)
	}
}

func TestUntrustedLines_KeepsTheCutTheAPIMade(t *testing.T) {
	if got := untrustedLines([]string{"a", "b"}, true); got.Text != "a\nb" || !got.Truncated {
		t.Errorf("got %+v", got)
	}
	if got := untrustedLines(nil, false); got.Text != "" || got.Truncated || !got.Untrusted {
		t.Errorf("empty logs: %+v", got)
	}
}

func TestRemoteScalar(t *testing.T) {
	t.Run("one line, scrubbed", func(t *testing.T) {
		got, cut := remoteScalar("web\n\x1b[31m token=abc")
		if got != "web token=[REDACTED]" || cut {
			t.Errorf("got %q cut=%v", got, cut)
		}
	})
	t.Run("capped", func(t *testing.T) {
		got, cut := remoteScalar(strings.Repeat("a", MaxRemoteScalarBytes+1))
		if len(got) != MaxRemoteScalarBytes || !cut {
			t.Errorf("len=%d cut=%v", len(got), cut)
		}
	})
}

func TestRemoteMap_MasksSensitiveKeysBeforeAnythingElse(t *testing.T) {
	got, cut := remoteMap(map[string]any{
		"password": "hunter2",
		"labels":   map[string]any{"db_token": "abc", "tier": "web"},
		"list":     []any{map[string]any{"api_key": "k"}, "smm_AbCdEfGhIjKlMnOp"},
	})
	raw, _ := json.Marshal(got)
	for _, leaked := range []string{"hunter2", `"abc"`, `"k"`, "smm_AbCdEf"} {
		if strings.Contains(string(raw), leaked) {
			t.Errorf("%s leaked: %s", leaked, raw)
		}
	}
	if !strings.Contains(string(raw), "web") || cut {
		t.Errorf("harmless value lost or spurious cut=%v: %s", cut, raw)
	}
}

func TestRemoteMap_SanitizesKeys(t *testing.T) {
	got, _ := remoteMap(map[string]any{"a\x1b[31m\nb": "v"})
	if _, ok := got["ab"]; !ok || len(got) != 1 {
		t.Errorf("keys = %v", got)
	}
}

func TestRemoteMap_DepthBound(t *testing.T) {
	nested := map[string]any{"v": 1}
	for range 5 {
		nested = map[string]any{"n": nested}
	}
	got, cut := remoteMap(nested) // depth 7 in total
	if !cut {
		t.Error("a map deeper than MaxRemoteDepth must be flagged truncated")
	}
	if depth := mapDepth(got); depth > MaxRemoteDepth {
		t.Errorf("depth = %d, cap is %d", depth, MaxRemoteDepth)
	}
}

func mapDepth(v any) int {
	switch x := v.(type) {
	case map[string]any:
		deepest := 0
		for _, child := range x {
			deepest = max(deepest, mapDepth(child))
		}
		return deepest + 1
	case []any:
		deepest := 0
		for _, child := range x {
			deepest = max(deepest, mapDepth(child))
		}
		return deepest + 1
	}
	return 0
}

func TestRemoteMap_EntryBound(t *testing.T) {
	big := make(map[string]any, 500)
	for i := range 500 {
		big[fmt.Sprintf("k%03d", i)] = i
	}
	got, cut := remoteMap(map[string]any{"big": big, "list": make([]any, 500)})
	if !cut {
		t.Error("truncation not flagged")
	}
	if n := len(got["big"].(map[string]any)); n != MaxRemoteEntries {
		t.Errorf("map entries = %d, want %d", n, MaxRemoteEntries)
	}
	if n := len(got["list"].([]any)); n != MaxRemoteEntries {
		t.Errorf("list entries = %d, want %d", n, MaxRemoteEntries)
	}
	if _, kept := got["big"].(map[string]any)["k000"]; !kept {
		t.Error("entry bound must keep the first keys in sorted order")
	}
}

func TestRemoteMap_NilStaysNil(t *testing.T) {
	if got, cut := remoteMap(nil); got != nil || cut {
		t.Errorf("got %v cut=%v", got, cut)
	}
}

func TestOperatorLine(t *testing.T) {
	if got := operatorLine("web\n\x1b[31m-1"); got != "web-1" {
		t.Errorf("got %q", got)
	}
	if got := operatorLine(strings.Repeat("n", 1000)); len(got) != MaxRemoteScalarBytes {
		t.Errorf("len = %d", len(got))
	}
}
