package mcp

import (
	"encoding/json"
	"errors"

	smerr "github.com/autarquico/supermgmt/internal/errors"
)

// correlationIDDetail is the smerr.Error.Details key under which the client
// keeps the correlation ID of a failed API call.
const correlationIDDetail = "correlation_id"

// toolError is what a failed tool call carries to the model: the API error
// code, reason and correlation ID, never internal text. Message is set only
// by this package, for failures it detects itself (ambiguous names, bad
// arguments); text that came from the API or the network is never copied.
type toolError struct {
	Code          smerr.Code   `json:"code"`
	Reason        smerr.Reason `json:"reason,omitempty"`
	CorrelationID string       `json:"correlation_id,omitempty"`
	Message       string       `json:"message,omitempty"`
}

// Error is the JSON text the SDK puts in the isError tool result.
func (e *toolError) Error() string {
	text, err := json.Marshal(e)
	if err != nil {
		return `{"code":"INTERNAL"}`
	}
	return string(text)
}

func invalidArgument(message string) *toolError {
	return &toolError{Code: smerr.CodeInvalidArgument, Message: message}
}

func ambiguousTarget(message string) *toolError {
	return &toolError{Code: smerr.CodeInvalidArgument, Reason: smerr.ReasonAmbiguousTarget, Message: message}
}

func targetNotFound(message string) *toolError {
	return &toolError{Code: smerr.CodeNotFound, Message: message}
}

// toolFailure turns any error from an API call or from resolution into the
// error a tool returns.
func toolFailure(err error) *toolError {
	var local *toolError
	if errors.As(err, &local) {
		return local
	}
	var api *smerr.Error
	if errors.As(err, &api) {
		id, _ := api.Details[correlationIDDetail].(string)
		return &toolError{Code: api.Code, Reason: api.Reason, CorrelationID: id}
	}
	return &toolError{Code: smerr.CodeInternal}
}
