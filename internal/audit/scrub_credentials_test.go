package audit

import (
	"strings"
	"testing"
)

func TestScrubCredentials(t *testing.T) {
	jwt := "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.c2lnbmF0dXJl"
	tests := []struct {
		name string
		in   string
		want string
	}{
		{"bearer", "Authorization: Bearer abc.def", "Authorization: [REDACTED] [REDACTED]"},
		{"pem", "-----BEGIN PRIVATE KEY-----\nMIIE\n-----END PRIVATE KEY-----", Redacted},
		{"mcp token", "token smm_AbCdEfGh12345678 here", "token [REDACTED] here"},
		{"api token", "smt_AbCdEfGh12345678", Redacted},
		{"session token", "sms_AbCdEfGh12345678", Redacted},
		{"short sm prefix is not a token", "smm_short", "smm_short"},
		{"jwt", "got " + jwt + " ok", "got [REDACTED] ok"},
		{"equals pair", "password=hunter2 next", "password=[REDACTED] next"},
		{"colon pair", "api_key: abc123", "api_key: [REDACTED]"},
		{"json pair", `{"api_key": "abc 123", "name": "web"}`, `{"api_key": "[REDACTED]", "name": "web"}`},
		{"single quoted", `token='abc def'`, `token='[REDACTED]'`},
		{"env style", "DB_PASSWORD=s3cret!", "DB_PASSWORD=[REDACTED]"},
		{"query string", "https://x/y?token=abc&a=1", "https://x/y?token=[REDACTED]&a=1"},
		{"harmless pair untouched", "name=web status: running", "name=web status: running"},
		{"reference kept", "password_ref: secret://db/main", "password_ref: secret://db/main"},
		{"plain text untouched", "listening on :8080", "listening on :8080"},
		{"empty", "", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := ScrubCredentials(tt.in); got != tt.want {
				t.Errorf("ScrubCredentials(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}

func TestScrubCredentials_DoesNotDetectSecretsUnderHarmlessNames(t *testing.T) {
	in := "DB_URL=postgres://app:hunter2@db/main"
	if got := ScrubCredentials(in); got != in {
		t.Errorf("ScrubCredentials(%q) = %q; the documented limit is that this is not detected", in, got)
	}
}

func TestScrubCredentials_IsIdempotent(t *testing.T) {
	in := "password=x Bearer abc smm_AbCdEfGh12345678"
	once := ScrubCredentials(in)
	if twice := ScrubCredentials(once); twice != once {
		t.Errorf("not idempotent: %q then %q", once, twice)
	}
}

func TestScrubCredentials_HandlesLargeInput(t *testing.T) {
	in := strings.Repeat("line without secrets\n", 1<<16) + "password=x"
	got := ScrubCredentials(in)
	if !strings.HasSuffix(got, "password=[REDACTED]") {
		t.Errorf("tail not scrubbed: %q", got[len(got)-40:])
	}
}
