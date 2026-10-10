package audit

import (
	"context"

	"github.com/autarquico/supermgmt/internal/domain"
)

type correlationKey struct{}

// WithCorrelationID returns a context that carries id.
func WithCorrelationID(ctx context.Context, id domain.ID) context.Context {
	return context.WithValue(ctx, correlationKey{}, id)
}

// CorrelationID returns the correlation id carried by ctx, if any.
func CorrelationID(ctx context.Context) (domain.ID, bool) {
	id, ok := ctx.Value(correlationKey{}).(domain.ID)
	return id, ok && id != ""
}

// EnsureCorrelationID returns ctx unchanged when it already carries an id,
// otherwise a context carrying a fresh one, together with the id in effect.
func EnsureCorrelationID(ctx context.Context, gen domain.IDGenerator) (context.Context, domain.ID) {
	if id, ok := CorrelationID(ctx); ok {
		return ctx, id
	}
	id := gen.NewID()
	return WithCorrelationID(ctx, id), id
}
