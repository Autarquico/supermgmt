package mcp

import (
	"sort"
	"strings"
	"unicode/utf8"

	"github.com/autarquico/supermgmt/internal/audit"
	"github.com/autarquico/supermgmt/internal/textsafe"
)

// truncationMarker replaces a nested value that exceeds MaxRemoteDepth.
const truncationMarker = "[truncated]"

// untrustedText turns remote text into the Untrusted envelope: sanitized,
// then scrubbed (so a credential is never cut in half by a bound), then
// capped at MaxUntrustedLines and MaxUntrustedBytes.
func untrustedText(raw string) Untrusted {
	text := audit.ScrubCredentials(textsafe.Sanitize([]byte(raw)))
	text, cutLines := capLines(text, MaxUntrustedLines)
	text, cutBytes := capBytes(text, MaxUntrustedBytes)
	return Untrusted{Untrusted: true, Text: text, Truncated: cutLines || cutBytes}
}

// untrustedLines is untrustedText over log lines; alreadyTruncated carries a
// cut the API made.
func untrustedLines(lines []string, alreadyTruncated bool) Untrusted {
	u := untrustedText(strings.Join(lines, "\n"))
	u.Truncated = u.Truncated || alreadyTruncated
	return u
}

// remoteScalar sanitizes, scrubs and caps one remote string field to a
// single line of at most MaxRemoteScalarBytes.
func remoteScalar(raw string) (text string, truncated bool) {
	return capBytes(audit.ScrubCredentials(textsafe.Line(raw)), MaxRemoteScalarBytes)
}

// operatorLine bounds a field the operator authored (node and app names,
// environment, tags): stripped to one line and capped, not scrubbed.
func operatorLine(raw string) string {
	text, _ := capBytes(textsafe.Line(raw), MaxRemoteScalarBytes)
	return text
}

// remoteMap makes a remote-discovered map safe for a model. Sensitive keys
// are masked structurally (audit.RedactMap) before anything is serialized;
// then keys and strings are sanitized, scrubbed and capped, and the shape is
// bounded by MaxRemoteDepth and MaxRemoteEntries. truncated reports any cut.
func remoteMap(m map[string]any) (out map[string]any, truncated bool) {
	if m == nil {
		return nil, false
	}
	return boundMap(audit.RedactMap(m), 1, &truncated), truncated
}

func boundMap(m map[string]any, depth int, truncated *bool) map[string]any {
	keys := make([]string, 0, len(m))
	for key := range m {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	if len(keys) > MaxRemoteEntries {
		keys, *truncated = keys[:MaxRemoteEntries], true
	}
	out := make(map[string]any, len(keys))
	for _, key := range keys {
		out[boundText(key, truncated)] = boundValue(m[key], depth+1, truncated)
	}
	return out
}

func boundList(list []any, depth int, truncated *bool) []any {
	if len(list) > MaxRemoteEntries {
		list, *truncated = list[:MaxRemoteEntries], true
	}
	out := make([]any, len(list))
	for i, item := range list {
		out[i] = boundValue(item, depth+1, truncated)
	}
	return out
}

func boundValue(v any, depth int, truncated *bool) any {
	switch x := v.(type) {
	case string:
		return boundText(x, truncated)
	case map[string]any:
		if depth > MaxRemoteDepth {
			*truncated = true
			return truncationMarker
		}
		return boundMap(x, depth, truncated)
	case []any:
		if depth > MaxRemoteDepth {
			*truncated = true
			return truncationMarker
		}
		return boundList(x, depth, truncated)
	}
	return v
}

func boundText(raw string, truncated *bool) string {
	text, cut := remoteScalar(raw)
	*truncated = *truncated || cut
	return text
}

// capLines keeps the first limit lines of text.
func capLines(text string, limit int) (string, bool) {
	end := 0
	for range limit {
		next := strings.IndexByte(text[end:], '\n')
		if next < 0 {
			return text, false
		}
		end += next + 1
	}
	if end >= len(text) {
		return text, false
	}
	return strings.TrimSuffix(text[:end], "\n"), true
}

// capBytes cuts text to at most limit bytes on a rune boundary.
func capBytes(text string, limit int) (string, bool) {
	if len(text) <= limit {
		return text, false
	}
	end := limit
	for end > 0 && !utf8.RuneStart(text[end]) {
		end--
	}
	return text[:end], true
}
