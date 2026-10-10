package audit

import (
	"context"
	"testing"

	"github.com/autarquico/supermgmt/internal/domain"
	"github.com/autarquico/supermgmt/internal/domain/domaintest"
)

func TestCorrelationIDRoundTrip(t *testing.T) {
	ctx := context.Background()
	if _, ok := CorrelationID(ctx); ok {
		t.Fatal("a fresh context must not carry a correlation id")
	}
	ctx = WithCorrelationID(ctx, "c-1")
	if id, ok := CorrelationID(ctx); !ok || id != "c-1" {
		t.Errorf("CorrelationID = %q, %v", id, ok)
	}
}

func TestEmptyCorrelationIDCountsAsAbsent(t *testing.T) {
	if _, ok := CorrelationID(WithCorrelationID(context.Background(), "")); ok {
		t.Error("an empty id must not count as present")
	}
}

func TestEnsureCorrelationIDKeepsExisting(t *testing.T) {
	gen := domaintest.NewSequentialIDs()
	ctx := WithCorrelationID(context.Background(), "existing")

	got, id := EnsureCorrelationID(ctx, gen)

	if id != "existing" || got != ctx {
		t.Errorf("EnsureCorrelationID replaced an existing id: %q", id)
	}
	if next := gen.NewID(); next != "00000000-0001-7000-8000-000000000000" {
		t.Errorf("generator was consumed although an id existed (next = %s)", next)
	}
}

func TestEnsureCorrelationIDGeneratesOnce(t *testing.T) {
	gen := domaintest.NewSequentialIDs()

	ctx, id := EnsureCorrelationID(context.Background(), gen)
	again, sameID := EnsureCorrelationID(ctx, gen)

	if id == "" || id != sameID {
		t.Errorf("ids = %q then %q, want one stable generated id", id, sameID)
	}
	if fromCtx, ok := CorrelationID(again); !ok || fromCtx != domain.ID(id) {
		t.Errorf("context carries %q, want %q", fromCtx, id)
	}
}
