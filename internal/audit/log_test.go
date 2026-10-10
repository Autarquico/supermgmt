package audit

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

const testKey = "-----BEGIN OPENSSH PRIVATE KEY-----\n" + plaintext + "\n-----END OPENSSH PRIVATE KEY-----"

// logSample emits one record exercising every redaction path.
func logSample(l *slog.Logger, ctx context.Context) {
	l = WithComponent(l, "api")
	l.InfoContext(ctx, "login failed for header Authorization: Bearer "+plaintext,
		"user", "alice",
		"password", plaintext,
		"typed", Secret(plaintext),
		"credential_ref", "secret://providers/home-pve/token",
		"err", errors.New("dial: Bearer "+plaintext+" rejected"),
		"key", testKey,
		"payload", map[string]any{"token": plaintext, "ok": "yes"},
		slog.Group("req",
			slog.String("authorization", "Basic "+plaintext+"=="),
			slog.String("path", "/api/v1/nodes"),
			slog.Group("headers", slog.String("Cookie", plaintext), slog.Int("count", 2)),
		),
		slog.Group("session", slog.String("id", plaintext)),
	)
}

func golden(t *testing.T, name string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatal(err)
	}
	return strings.TrimRight(string(b), "\n")
}

func TestGoldenJSONLogLine(t *testing.T) {
	var buf bytes.Buffer
	ctx := WithCorrelationID(context.Background(), "00000000-0001-7000-8000-000000000000")

	logSample(NewLogger(&buf, FormatJSON, slog.LevelInfo), ctx)

	if strings.Contains(buf.String(), plaintext) {
		t.Fatalf("JSON log leaked the secret: %s", buf.String())
	}
	var record map[string]any
	if err := json.Unmarshal(buf.Bytes(), &record); err != nil {
		t.Fatal(err)
	}
	delete(record, "time")
	got, err := json.MarshalIndent(record, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if want := golden(t, "log.json.golden"); string(got) != want {
		t.Errorf("JSON log line differs from testdata/log.json.golden.\ngot:\n%s", got)
	}
}

func TestGoldenTextLogLine(t *testing.T) {
	var buf bytes.Buffer
	ctx := WithCorrelationID(context.Background(), "00000000-0001-7000-8000-000000000000")

	logSample(NewLogger(&buf, FormatText, slog.LevelInfo), ctx)

	if strings.Contains(buf.String(), plaintext) {
		t.Fatalf("text log leaked the secret: %s", buf.String())
	}
	got := regexp.MustCompile(`^time=\S+ `).ReplaceAllString(strings.TrimRight(buf.String(), "\n"), "")
	if want := golden(t, "log.text.golden"); got != want {
		t.Errorf("text log line differs from testdata/log.text.golden.\ngot:\n%s", got)
	}
}

func TestLoggerAddsCorrelationIDOnlyWhenPresent(t *testing.T) {
	var buf bytes.Buffer
	l := NewLogger(&buf, FormatJSON, slog.LevelInfo)

	l.InfoContext(context.Background(), "without")
	l.InfoContext(WithCorrelationID(context.Background(), "c-9"), "with")

	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	if strings.Contains(lines[0], "correlation_id") {
		t.Errorf("record without a correlation id carries one: %s", lines[0])
	}
	if !strings.Contains(lines[1], `"correlation_id":"c-9"`) {
		t.Errorf("record lacks the context correlation id: %s", lines[1])
	}
}

func TestLoggerRedactsPreformattedAttrs(t *testing.T) {
	var buf bytes.Buffer
	l := NewLogger(&buf, FormatJSON, slog.LevelInfo).With("token", plaintext, "note", "Bearer "+plaintext)

	l.Info("hello")

	if strings.Contains(buf.String(), plaintext) {
		t.Errorf("With() attributes leaked: %s", buf.String())
	}
}

func TestLoggerRedactsInsideSensitiveGroupViaWithGroup(t *testing.T) {
	var buf bytes.Buffer
	l := NewLogger(&buf, FormatJSON, slog.LevelInfo).WithGroup("credentials")

	l.Info("hello", "value", plaintext)

	if strings.Contains(buf.String(), plaintext) {
		t.Errorf("WithGroup attributes leaked: %s", buf.String())
	}
}

func TestLoggerHonorsLevel(t *testing.T) {
	var buf bytes.Buffer
	l := NewLogger(&buf, FormatText, slog.LevelWarn)

	l.Info("quiet")
	l.Warn("loud")

	if out := buf.String(); strings.Contains(out, "quiet") || !strings.Contains(out, "loud") {
		t.Errorf("level filtering wrong: %q", out)
	}
}

func TestLoggerComponent(t *testing.T) {
	var buf bytes.Buffer
	WithComponent(NewLogger(&buf, FormatJSON, slog.LevelInfo), "jobs").Info("tick")

	if !strings.Contains(buf.String(), `"component":"jobs"`) {
		t.Errorf("missing component: %s", buf.String())
	}
}

func TestUnknownFormatFallsBackToJSON(t *testing.T) {
	var buf bytes.Buffer
	NewLogger(&buf, Format("yaml"), slog.LevelInfo).Info("x")

	if !json.Valid(buf.Bytes()) {
		t.Errorf("fallback output is not JSON: %s", buf.String())
	}
}
