package mcp

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"

	smerr "github.com/autarquico/supermgmt/internal/errors"
)

func TestToolFailure_APIErrorKeepsCodeReasonAndCorrelationOnly(t *testing.T) {
	api := smerr.New(smerr.CodeConflict, smerr.ReasonPlanStale, "plan 0190 changed: password=hunter2")
	api.Details = map[string]any{correlationIDDetail: "corr-9", "query": "SELECT 1"}

	got := toolFailure(fmt.Errorf("get plan: %w", api))

	want := toolError{Code: smerr.CodeConflict, Reason: smerr.ReasonPlanStale, CorrelationID: "corr-9"}
	if *got != want {
		t.Errorf("failure = %+v, want %+v", *got, want)
	}
	for _, leak := range []string{"hunter2", "SELECT", "changed"} {
		if strings.Contains(got.Error(), leak) {
			t.Errorf("error text leaks %q: %s", leak, got.Error())
		}
	}
}

func TestToolFailure_UnknownErrorsAreInternalWithoutText(t *testing.T) {
	got := toolFailure(errors.New("dial unix /run/supermgmt/sm.sock: connect: permission denied"))

	if got.Code != smerr.CodeInternal || got.Message != "" || strings.Contains(got.Error(), "sock") {
		t.Errorf("failure = %s", got.Error())
	}
}

func TestToolFailure_LocalErrorsKeepTheirMessage(t *testing.T) {
	local := ambiguousTarget("2 nodes match \"web\"; use an id")

	got := toolFailure(fmt.Errorf("resolve: %w", local))

	if got != local {
		t.Errorf("failure = %+v, want the local error unchanged", got)
	}
}

func TestToolError_TextIsTheErrorJSON(t *testing.T) {
	var decoded toolError
	text := (&toolError{Code: smerr.CodeNotFound, CorrelationID: "c1"}).Error()

	if err := json.Unmarshal([]byte(text), &decoded); err != nil {
		t.Fatalf("error text %q is not JSON: %v", text, err)
	}
	if decoded.Code != smerr.CodeNotFound || decoded.CorrelationID != "c1" {
		t.Errorf("decoded = %+v", decoded)
	}
}
