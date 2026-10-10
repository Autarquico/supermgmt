package plan

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"slices"
	"strconv"
	"unicode/utf16"
	"unicode/utf8"
)

// canonicalizeJSON re-serializes one JSON document per RFC 8785 (JCS),
// restricted to what plans may contain:
//
//   - object keys are sorted by UTF-16 code units;
//   - strings use the ES6 JSON.stringify escapes; "/" and non-ASCII stay literal;
//   - numbers must be integers in [0, 2^53-1] with no fraction or exponent
//     (JCS's float formatting is deliberately not implemented: plans forbid floats);
//   - invalid UTF-8, lone surrogate escapes, duplicate keys, trailing data and
//     nesting deeper than maxDepth are rejected.
func canonicalizeJSON(raw []byte) ([]byte, error) {
	if !utf8.Valid(raw) {
		return nil, invalid("JSON is not valid UTF-8")
	}
	if err := rejectLoneSurrogates(raw); err != nil {
		return nil, err
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	tree, err := decodeTree(dec, 1)
	if err != nil {
		return nil, err
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return nil, invalid("trailing data after JSON value")
	}
	var out bytes.Buffer
	if err := writeTree(&out, tree); err != nil {
		return nil, err
	}
	return out.Bytes(), nil
}

// decodeTree reads one value as nil, bool, string, json.Number, []any or
// map[string]any. It uses the token API so duplicate keys are detectable.
func decodeTree(dec *json.Decoder, depth int) (any, error) {
	if depth > maxDepth {
		return nil, invalid("JSON is nested deeper than %d levels", maxDepth)
	}
	tok, err := dec.Token()
	if err != nil {
		return nil, invalid("malformed JSON: %v", err)
	}
	delim, isDelim := tok.(json.Delim)
	if !isDelim {
		return tok, nil // nil, bool, string or json.Number
	}
	if delim == '[' {
		return decodeArray(dec, depth)
	}
	return decodeObject(dec, depth)
}

func decodeArray(dec *json.Decoder, depth int) (any, error) {
	items := []any{}
	for dec.More() {
		item, err := decodeTree(dec, depth+1)
		if err != nil {
			return nil, err
		}
		items = append(items, item)
	}
	if _, err := dec.Token(); err != nil { // closing ]
		return nil, invalid("malformed JSON: %v", err)
	}
	return items, nil
}

func decodeObject(dec *json.Decoder, depth int) (any, error) {
	members := map[string]any{}
	for dec.More() {
		keyTok, err := dec.Token()
		if err != nil {
			return nil, invalid("malformed JSON: %v", err)
		}
		key, ok := keyTok.(string)
		if !ok {
			return nil, invalid("object key is not a string")
		}
		if _, dup := members[key]; dup {
			return nil, invalid("duplicate object key %q", key)
		}
		if members[key], err = decodeTree(dec, depth+1); err != nil {
			return nil, err
		}
	}
	if _, err := dec.Token(); err != nil { // closing }
		return nil, invalid("malformed JSON: %v", err)
	}
	return members, nil
}

func writeTree(out *bytes.Buffer, v any) error {
	switch t := v.(type) {
	case nil:
		out.WriteString("null")
	case bool:
		out.WriteString(strconv.FormatBool(t))
	case string:
		writeString(out, t)
	case json.Number:
		digits, err := integerText(string(t))
		if err != nil {
			return err
		}
		out.WriteString(digits)
	case []any:
		out.WriteByte('[')
		for i, item := range t {
			if i > 0 {
				out.WriteByte(',')
			}
			if err := writeTree(out, item); err != nil {
				return err
			}
		}
		out.WriteByte(']')
	case map[string]any:
		return writeObject(out, t)
	default:
		return invalid("unsupported JSON value %T", v)
	}
	return nil
}

type member struct {
	key   string
	units []uint16
}

func writeObject(out *bytes.Buffer, obj map[string]any) error {
	members := make([]member, 0, len(obj))
	for k := range obj {
		members = append(members, member{key: k, units: utf16.Encode([]rune(k))})
	}
	slices.SortFunc(members, func(a, b member) int { return slices.Compare(a.units, b.units) })

	out.WriteByte('{')
	for i, m := range members {
		if i > 0 {
			out.WriteByte(',')
		}
		writeString(out, m.key)
		out.WriteByte(':')
		if err := writeTree(out, obj[m.key]); err != nil {
			return err
		}
	}
	out.WriteByte('}')
	return nil
}

// writeString emits s as ES6 JSON.stringify does: short escapes for \b \t \n
// \f \r, lowercase \u00xx for other C0 controls, backslash-escaped quote and
// backslash, everything else (including "/" and non-ASCII) verbatim.
func writeString(out *bytes.Buffer, s string) {
	const hex = "0123456789abcdef"
	out.WriteByte('"')
	for i := 0; i < len(s); i++ {
		switch c := s[i]; {
		case c == '"':
			out.WriteString(`\"`)
		case c == '\\':
			out.WriteString(`\\`)
		case c == '\b':
			out.WriteString(`\b`)
		case c == '\t':
			out.WriteString(`\t`)
		case c == '\n':
			out.WriteString(`\n`)
		case c == '\f':
			out.WriteString(`\f`)
		case c == '\r':
			out.WriteString(`\r`)
		case c < 0x20:
			out.WriteString(`\u00`)
			out.WriteByte(hex[c>>4])
			out.WriteByte(hex[c&0xf])
		default:
			out.WriteByte(c)
		}
	}
	out.WriteByte('"')
}

// integerText validates a JSON number literal as an integer in [0, 2^53-1] and
// returns its canonical digits. It never goes through float parsing.
func integerText(literal string) (string, error) {
	if literal == "" {
		return "", errors.New("empty number")
	}
	for _, r := range literal {
		if r < '0' || r > '9' {
			if r == '-' && literal[0] == '-' {
				return "", fmt.Errorf("number %s is negative; plans allow only [0, 2^53-1]", literal)
			}
			return "", fmt.Errorf("number %s is not an integer; floats are forbidden in plans", literal)
		}
	}
	value, err := strconv.ParseUint(literal, 10, 64)
	if err != nil || value > maxSafeInteger {
		return "", fmt.Errorf("number %s is outside [0, 2^53-1]", literal)
	}
	return strconv.FormatUint(value, 10), nil
}

// rejectLoneSurrogates scans the raw text for \uD800-\uDFFF escapes that are
// not a well-formed high+low pair. encoding/json would silently turn them into
// U+FFFD, which RFC 8785 forbids, so they must be caught before decoding.
func rejectLoneSurrogates(raw []byte) error {
	inString := false
	for i := 0; i < len(raw); i++ {
		c := raw[i]
		switch {
		case !inString:
			inString = c == '"'
		case c == '"':
			inString = false
		case c == '\\':
			next, err := skipEscape(raw, i)
			if err != nil {
				return err
			}
			i = next
		}
	}
	return nil
}

// skipEscape returns the index of the last byte of the escape sequence that
// starts at raw[i] (a backslash). Malformed escapes are left to the decoder.
func skipEscape(raw []byte, i int) (int, error) {
	if i+1 >= len(raw) {
		return i, nil
	}
	if raw[i+1] != 'u' {
		return i + 1, nil
	}
	unit, ok := hexUnit(raw[i+2:])
	if !ok {
		return i + 1, nil
	}
	last := i + 5
	switch {
	case unit >= 0xdc00 && unit <= 0xdfff:
		return 0, invalid("lone low surrogate \\u%04x", unit)
	case unit >= 0xd800 && unit <= 0xdbff:
		if !followedByLowSurrogate(raw[last+1:]) {
			return 0, invalid("lone high surrogate \\u%04x", unit)
		}
		last += 6
	}
	return last, nil
}

func followedByLowSurrogate(rest []byte) bool {
	if len(rest) < 6 || rest[0] != '\\' || rest[1] != 'u' {
		return false
	}
	unit, ok := hexUnit(rest[2:])
	return ok && unit >= 0xdc00 && unit <= 0xdfff
}

// hexUnit parses four hex digits at the start of b.
func hexUnit(b []byte) (uint16, bool) {
	if len(b) < 4 {
		return 0, false
	}
	value, err := strconv.ParseUint(string(b[:4]), 16, 16)
	return uint16(value), err == nil
}
