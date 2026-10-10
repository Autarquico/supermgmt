package plan

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"unicode/utf8"
)

func readFile(t testing.TB, path string) []byte {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func glob(t testing.TB, pattern string) []string {
	t.Helper()
	files, err := filepath.Glob(pattern)
	if err != nil || len(files) == 0 {
		t.Fatalf("no files match %s (err %v)", pattern, err)
	}
	return files
}

func TestRFC8785ApplicableVectorsAreByteIdentical(t *testing.T) {
	for _, input := range glob(t, "testdata/rfc8785/applicable/*.input.json") {
		name := strings.TrimSuffix(filepath.Base(input), ".input.json")
		t.Run(name, func(t *testing.T) {
			want := readFile(t, strings.TrimSuffix(input, ".input.json")+".expected.json")
			got, err := canonicalizeJSON(readFile(t, input))
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(got, want) {
				t.Fatalf("canonical output differs\n got: %s\nwant: %s", got, want)
			}
		})
	}
}

func TestRFC8785RejectedVectors(t *testing.T) {
	for _, input := range glob(t, "testdata/rfc8785/rejected/*.json") {
		t.Run(filepath.Base(input), func(t *testing.T) {
			if out, err := canonicalizeJSON(readFile(t, input)); err == nil {
				t.Fatalf("accepted, produced %s", out)
			}
		})
	}
	t.Run("appendix-b-numbers.txt", func(t *testing.T) {
		for _, literal := range strings.Fields(string(readFile(t, "testdata/rfc8785/rejected/appendix-b-numbers.txt"))) {
			if out, err := canonicalizeJSON([]byte(literal)); err == nil {
				t.Errorf("number %s accepted, produced %s", literal, out)
			}
		}
	})
}

func TestObjectKeysSortByUTF16CodeUnitsNotCodePoints(t *testing.T) {
	cases := []struct{ name, in, want string }{
		{
			"U+FFFF versus U+1F600 (D83D DE00)",
			`{"￿":1,"😀":2}`,
			"{\"\U0001F600\":2,\"￿\":1}",
		},
		{
			"U+10000 (D800 DC00) versus U+E000",
			`{"":1,"𐀀":2}`,
			"{\"\U00010000\":2,\"\":1}",
		},
		{
			"shorter prefix first",
			`{"ab":1,"a":2,"":3,"aa":4}`,
			`{"":3,"a":2,"aa":4,"ab":1}`,
		},
		{
			"keys are compared unescaped",
			`{"\n":1,"\u0009":2,"\u001f":3}`,
			`{"\t":2,"\n":1,"\u001f":3}`,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := canonicalizeJSON([]byte(tc.in))
			if err != nil {
				t.Fatal(err)
			}
			if string(got) != tc.want {
				t.Fatalf("got  %q\nwant %q", got, tc.want)
			}
		})
	}
}

func TestStringEscapingFollowsES6JSONStringify(t *testing.T) {
	cases := []struct{ name, in, want string }{
		{"short escapes", `"\b\t\n\f\r"`, `"\b\t\n\f\r"`},
		{"other C0 controls are lowercase u00xx", `"\u0000\u0001\u000b\u000e\u001f"`, `"\u0000\u0001\u000b\u000e\u001f"`},
		{"quote and backslash", `"\"\\"`, `"\"\\"`},
		{"solidus is not escaped", `"a\/b/c"`, `"a/b/c"`},
		{"DEL stays literal", "\"\u007f\"", "\"\u007f\""},
		{"no HTML escaping", `"<script>&'<"`, `"<script>&'<"`},
		{"non-ASCII stays literal", `"é€😀"`, "\"é€\U0001F600\""},
		{"U+2028 and U+2029 stay literal", `"  "`, "\"  \""},
		{"escaped and literal forms are one string", `"AA"`, `"AA"`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := canonicalizeJSON([]byte(tc.in))
			if err != nil {
				t.Fatal(err)
			}
			if string(got) != tc.want {
				t.Fatalf("got  %q\nwant %q", got, tc.want)
			}
		})
	}
}

func TestNumbersAreIntegersInSafeRange(t *testing.T) {
	accepted := map[string]string{
		"0": "0", "7": "7", "9007199254740991": "9007199254740991", "[1,22]": "[1,22]",
	}
	for in, want := range accepted {
		got, err := canonicalizeJSON([]byte(in))
		if err != nil || string(got) != want {
			t.Errorf("%s -> %q, %v; want %q", in, got, err, want)
		}
	}
	for _, in := range []string{
		"9007199254740992", "18446744073709551616", "-1", "-0", "0.0", "1.0", "1e3", "1E3", "1e-3", "0.5", "2.5e+2",
	} {
		if out, err := canonicalizeJSON([]byte(in)); err == nil {
			t.Errorf("%s accepted as %s", in, out)
		}
	}
}

func TestMalformedAndHostileInput(t *testing.T) {
	deep := func(n int) string { return strings.Repeat("[", n) + strings.Repeat("]", n) }
	rejected := map[string]string{
		"empty":                    "",
		"whitespace only":          "  ",
		"unterminated object":      `{"a":1`,
		"missing value":            `{"a":}`,
		"trailing comma":           `[1,]`,
		"missing colon":            `{"a" 1}`,
		"bare word":                `nul`,
		"non-string key":           `{1:2}`,
		"single quotes":            `{'a':1}`,
		"truncated escape":         `"\u12"`,
		"truncated string":         `"abc`,
		"two documents":            `1 2`,
		"nested too deep":          deep(maxDepth + 1),
		"object nested too deep":   strings.Repeat(`{"a":`, maxDepth+1) + "1" + strings.Repeat("}", maxDepth+1),
		"unterminated lone escape": `"\`,
	}
	for name, in := range rejected {
		if out, err := canonicalizeJSON([]byte(in)); err == nil {
			t.Errorf("%s: accepted as %s", name, out)
		}
	}
	if _, err := canonicalizeJSON([]byte(deep(maxDepth))); err != nil {
		t.Errorf("nesting at the limit rejected: %v", err)
	}
}

func TestWhitespaceIsDroppedAndEmptyContainersSurvive(t *testing.T) {
	got, err := canonicalizeJSON([]byte(" \n{ \"b\" : [ ] ,\t\"a\" : { } } \n"))
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != `{"a":{},"b":[]}` {
		t.Fatalf("got %s", got)
	}
}

func FuzzCanonicalizeJSON(f *testing.F) {
	for _, pattern := range []string{"testdata/rfc8785/applicable/*.input.json", "testdata/rfc8785/rejected/*.json"} {
		for _, file := range glob(f, pattern) {
			f.Add(readFile(f, file))
		}
	}
	for _, seed := range []string{`{}`, `[]`, `"😀"`, `{"a":[1,2,{"b":null}]}`, `"\ud800"`, "\xff", `{"a":1,"a":2}`} {
		f.Add([]byte(seed))
	}
	f.Fuzz(func(t *testing.T, input []byte) {
		out, err := canonicalizeJSON(input) // must never panic
		if err != nil {
			return
		}
		if !utf8.Valid(out) || !json.Valid(out) {
			t.Fatalf("output is not valid UTF-8 JSON: %q", out)
		}
		again, err := canonicalizeJSON(out)
		if err != nil || !bytes.Equal(again, out) {
			t.Fatalf("not idempotent: JCS(%q) = %q, then %q, %v", input, out, again, err)
		}
	})
}
