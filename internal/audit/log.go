package audit

import (
	"context"
	"io"
	"log/slog"
	"slices"
)

// Format selects the log encoding: JSON for servers, text for humans (spec §33).
type Format string

const (
	FormatJSON Format = "json"
	FormatText Format = "text"
)

// NewLogger builds a logger that adds the context's correlation_id and
// redacts secrets: attributes under sensitive keys or groups, Secret values,
// and bearer tokens, basic credentials and private keys inside strings,
// messages and error texts. An unknown format falls back to JSON.
//
// Note: slog places context attributes inside an open WithGroup, so a logger
// derived with WithGroup nests correlation_id in that group.
func NewLogger(w io.Writer, format Format, level slog.Level) *slog.Logger {
	opts := &slog.HandlerOptions{Level: level, ReplaceAttr: redactAttr}
	var base slog.Handler = slog.NewJSONHandler(w, opts)
	if format == FormatText {
		base = slog.NewTextHandler(w, opts)
	}
	return slog.New(correlationHandler{base})
}

// WithComponent returns a logger that tags every record with component=name.
func WithComponent(l *slog.Logger, name string) *slog.Logger {
	return l.With(slog.String("component", name))
}

func redactAttr(groups []string, a slog.Attr) slog.Attr {
	a.Value = a.Value.Resolve()
	if sensitiveKey(a.Key) && !keepAsReference(a.Key, a.Value.Any()) || slices.ContainsFunc(groups, sensitiveKey) {
		return slog.String(a.Key, Redacted)
	}
	switch a.Value.Kind() { //nolint:exhaustive // other kinds carry no free text
	case slog.KindString:
		return slog.String(a.Key, ScrubString(a.Value.String()))
	case slog.KindAny:
		return slog.Any(a.Key, redactValue(a.Value.Any()))
	}
	return a
}

// correlationHandler adds correlation_id from the record's context.
type correlationHandler struct{ slog.Handler }

func (h correlationHandler) Handle(ctx context.Context, r slog.Record) error {
	if id, ok := CorrelationID(ctx); ok {
		r.AddAttrs(slog.String("correlation_id", string(id)))
	}
	return h.Handler.Handle(ctx, r)
}

func (h correlationHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	return correlationHandler{h.Handler.WithAttrs(attrs)}
}

func (h correlationHandler) WithGroup(name string) slog.Handler {
	return correlationHandler{h.Handler.WithGroup(name)}
}
