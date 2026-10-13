package app

import (
	"context"
	"testing"

	"github.com/autarquico/supermgmt/internal/api/wire"
	"github.com/autarquico/supermgmt/internal/config"
	smerr "github.com/autarquico/supermgmt/internal/errors"
)

func TestValidateImportAppSecretValues(t *testing.T) {
	tests := []struct {
		name   string
		secret string
		value  string
		reject bool
	}{
		{"plain app secret", "apps/web/db_url", "postgres://u:p@db/app", false},
		{"punctuation is byte-exact material", "apps/web/token", `a$b "c" #d =e \f ünï `, false},
		{"leading and trailing spaces", "apps/web/token", "  padded  ", false},
		{"line feed", "apps/web/token", "a\nb", true},
		{"carriage return", "apps/web/token", "a\rb", true},
		{"trailing line feed", "apps/web/token", "value\n", true},
		{"NUL", "apps/web/token", "a\x00b", true},
		{"invalid UTF-8", "apps/web/token", "a\xffb", true},
		{"other secrets keep their newlines", "demo/key", "-----BEGIN-----\nbody\n", false},
		{"prefix must be a path segment", "apps-extra/token", "a\nb", false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := validateImport(wire.ImportSecretRequest{Name: tc.secret, Value: tc.value})
			if tc.reject {
				if smerr.CodeOf(err) != smerr.CodeInvalidArgument {
					t.Fatalf("err = %v, want INVALID_ARGUMENT", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("err = %v, want nil", err)
			}
		})
	}
}

func TestImportSecretRefusesAppSecretWithLineBreakBeforeStagingAnything(t *testing.T) {
	k := newKeysFixture(t, config.ModeLocal)

	_, err := k.km.ImportSecret(context.Background(), k.caller(k.admin), wire.ImportSecretRequest{Name: "apps/web/token", Value: "a\nb"})

	if smerr.CodeOf(err) != smerr.CodeInvalidArgument {
		t.Fatalf("err = %v, want INVALID_ARGUMENT", err)
	}
	if rows := k.secretRows(); rows != 0 {
		t.Errorf("secret rows = %d, a refused value must not be staged", rows)
	}
}

func TestImportSecretAcceptsAppSecretOnOneLine(t *testing.T) {
	k := newKeysFixture(t, config.ModeLocal)

	res, err := k.km.ImportSecret(context.Background(), k.caller(k.admin), wire.ImportSecretRequest{Name: "apps/web/token", Value: "s3cr3t value"})

	mustf(t, err, "ImportSecret")
	if res.Pending == nil {
		t.Fatalf("result = %+v, want a pending job", res)
	}
}
