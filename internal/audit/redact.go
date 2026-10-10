// Package audit creates audit events, redacts secrets and builds the
// structured logger (spec §26, §30, §33). It never opens transactions: events
// are appended through an EventWriter that the database layer implements
// inside its own writer transaction.
package audit

import (
	"encoding/json"
	"log/slog"
	"reflect"
	"regexp"
	"strings"
)

// Redacted replaces every secret value in events and logs.
const Redacted = "[REDACTED]"

// Secret is a string that never reveals itself: every formatting and
// marshaling path yields Redacted. Reveal is the single, greppable way out.
type Secret string

func (Secret) String() string               { return Redacted }
func (Secret) GoString() string             { return Redacted }
func (Secret) MarshalJSON() ([]byte, error) { return []byte(`"` + Redacted + `"`), nil }
func (Secret) MarshalText() ([]byte, error) { return []byte(Redacted), nil }
func (Secret) LogValue() slog.Value         { return slog.StringValue(Redacted) }

// Reveal returns the plaintext. Call it only where the secret is consumed.
func (s Secret) Reveal() string { return string(s) }

// sensitiveKeyParts are matched case-insensitively as substrings of a key,
// with "-" read as "_": "db_password", "X-Api-Key" and "Authorization" are all
// caught. Over-redacting is the safe failure mode.
var sensitiveKeyParts = []string{
	"password", "passwd", "secret", "token", "authorization", "private_key",
	"privatekey", "credential", "api_key", "apikey", "cookie", "session",
	"passphrase", "dsn",
}

func sensitiveKey(key string) bool {
	lower := strings.ReplaceAll(strings.ToLower(key), "-", "_")
	for _, part := range sensitiveKeyParts {
		if strings.Contains(lower, part) {
			return true
		}
	}
	return false
}

var (
	bearerPattern     = regexp.MustCompile(`(?i)\bBearer\s+[A-Za-z0-9._~+/=-]+`)
	basicPattern      = regexp.MustCompile(`(?i)\bBasic\s+[A-Za-z0-9+/=_-]{8,}`)
	privateKeyPattern = regexp.MustCompile(`-----BEGIN [A-Z ]*PRIVATE KEY-----(?s:.*?)(?:-----END [A-Z ]*PRIVATE KEY-----|\z)`)
)

// referenceValue is the full grammar of a credential reference (spec §8.4):
// a value that names a secret without containing one.
var referenceValue = regexp.MustCompile(`^(?:secret://[A-Za-z0-9._@:/-]+|ssh-agent://default|file:///[A-Za-z0-9._@+:/-]+)$`)

// keepAsReference reports whether the value under key may stay visible: only
// an explicit reference field (name ending in _ref, such as credential_ref)
// holding a complete reference. Every other sensitive key is always masked,
// whatever its value looks like.
func keepAsReference(key string, value any) bool {
	ref, ok := value.(string)
	return ok && strings.HasSuffix(strings.ToLower(key), "_ref") && referenceValue.MatchString(ref)
}

// ScrubString removes bearer tokens, basic credentials and PEM private keys
// from s. secret:// references are kept: they point at a secret, they are not one.
func ScrubString(s string) string {
	s = privateKeyPattern.ReplaceAllString(s, Redacted)
	s = bearerPattern.ReplaceAllString(s, "Bearer "+Redacted)
	return basicPattern.ReplaceAllString(s, "Basic "+Redacted)
}

// RedactMap returns a deep copy of m with sensitive keys masked and string
// values scrubbed. Nested maps, slices and structs are traversed; m itself is
// never modified.
func RedactMap(m map[string]any) map[string]any {
	if m == nil {
		return nil
	}
	out := make(map[string]any, len(m))
	for key, value := range m {
		if sensitiveKey(key) && !keepAsReference(key, value) {
			out[key] = Redacted
			continue
		}
		out[key] = redactValue(value)
	}
	return out
}

func redactValue(v any) any {
	switch x := v.(type) {
	case nil:
		return nil
	case Secret:
		return Redacted
	case string:
		return ScrubString(x)
	case error:
		return ScrubString(x.Error())
	case map[string]any:
		return RedactMap(x)
	case []any:
		return redactSlice(x)
	}
	switch rv := reflect.ValueOf(v); rv.Kind() { //nolint:exhaustive // composite kinds share the JSON round trip
	case reflect.Bool, reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64,
		reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64, reflect.Float32, reflect.Float64:
		return v
	case reflect.String:
		return ScrubString(rv.String())
	}
	return redactViaJSON(v)
}

func redactSlice(s []any) []any {
	out := make([]any, len(s))
	for i, item := range s {
		out[i] = redactValue(item)
	}
	return out
}

// redactViaJSON handles every composite type (typed slices and maps, structs,
// pointers) uniformly: it re-reads the value as generic JSON, which honors
// Secret's marshaling, then redacts that. A value JSON cannot represent is
// masked entirely rather than risked.
func redactViaJSON(v any) any {
	raw, err := json.Marshal(v)
	if err != nil {
		return Redacted
	}
	var generic any
	if err := json.Unmarshal(raw, &generic); err != nil {
		return Redacted
	}
	return redactValue(generic)
}
