package audit

import (
	"regexp"
	"strings"
)

var (
	// superMgmtTokenPattern matches the token formats of spec §9 (sms_, smt_,
	// smb_, smj_, smm_).
	superMgmtTokenPattern = regexp.MustCompile(`sm[stbjm]_[A-Za-z0-9_-]{8,}`)
	jwtPattern            = regexp.MustCompile(`eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*`)
	// keyValuePattern finds `key=value`, `key: value` and `"key": "value"`.
	// Groups: 1 opening quote of the key, 2 key, 3 closing quote, 4 separator, 5 value.
	keyValuePattern = regexp.MustCompile(`(["']?)([A-Za-z0-9_.-]+)(["']?)(\s*[:=]\s*)("(?:[^"\\]|\\.)*"|'[^']*'|\[REDACTED\]|[^\s,;&"'}\]]+)`)
)

// ScrubCredentials removes the credentials that can be recognized by shape
// from text of remote origin: everything ScrubString removes, SuperMgmt
// tokens, JWTs, and the value of any key=value, key: value or "key": "value"
// pair whose key names a secret (the RedactMap rule).
//
// It cannot detect an arbitrary secret under a harmless name (DB_URL holding
// a password). That limit is part of the contract (ADR-0031).
func ScrubCredentials(s string) string {
	s = ScrubString(s)
	s = superMgmtTokenPattern.ReplaceAllString(s, Redacted)
	s = jwtPattern.ReplaceAllString(s, Redacted)
	return scrubPairs(s)
}

// scrubPairs masks the value of every pair with a sensitive key. A pair whose
// key is harmless is not consumed past its separator, so a pair nested in its
// value (a URL query) is still examined.
func scrubPairs(s string) string {
	var out strings.Builder
	for rest := s; ; {
		m := keyValuePattern.FindStringSubmatchIndex(rest)
		if m == nil {
			out.WriteString(rest)
			return out.String()
		}
		openQuote, key, closeQuote := rest[m[2]:m[3]], rest[m[4]:m[5]], rest[m[6]:m[7]]
		separator, value := rest[m[8]:m[9]], rest[m[10]:m[11]]
		if sensitiveKey(key) && keepAsReference(key, unquote(value)) {
			out.WriteString(rest[:m[1]])
			rest = rest[m[1]:]
			continue
		}
		if !sensitiveKey(key) {
			out.WriteString(rest[:m[10]])
			rest = rest[m[10]:]
			continue
		}
		out.WriteString(rest[:m[0]])
		out.WriteString(openQuote + key + closeQuote + separator + maskLike(value))
		rest = rest[m[1]:]
	}
}

func maskLike(value string) string {
	if quote := value[0]; quote == '"' || quote == '\'' {
		return string(quote) + Redacted + string(quote)
	}
	return Redacted
}

func unquote(value string) string {
	if n := len(value); n >= 2 && (value[0] == '"' || value[0] == '\'') && value[n-1] == value[0] {
		return value[1 : n-1]
	}
	return value
}
