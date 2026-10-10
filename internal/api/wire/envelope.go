// Package wire is the JSON contract of /api/v1 (spec §23) shared by the
// server (internal/api) and the typed client (internal/client): envelopes,
// headers, route paths, query parameters and DTOs. It holds no behavior
// beyond encoding helpers, so both sides compile against one definition.
package wire

import (
	smerr "github.com/autarquico/supermgmt/internal/errors"
)

// Headers with protocol meaning (spec §23, ADR-0014).
const (
	HeaderIdempotencyKey     = "Idempotency-Key"
	HeaderIdempotentReplayed = "Idempotent-Replayed"
	HeaderIfMatch            = "If-Match"
	HeaderCorrelationID      = "X-Correlation-Id"
	// HeaderAuthorization is refused on the Unix socket until M5 (401).
	HeaderAuthorization = "Authorization"
)

// ContentType is the media type of every request and response body.
const ContentType = "application/json"

// Envelope wraps every successful response: {"data":…,"meta":{…}}.
type Envelope[T any] struct {
	Data T    `json:"data"`
	Meta Meta `json:"meta"`
}

// Meta carries response metadata.
type Meta struct {
	CorrelationID string `json:"correlation_id,omitempty"`
}

// ErrorEnvelope wraps every error response: {"error":{…}}.
type ErrorEnvelope struct {
	Error Error `json:"error"`
}

// Error is the error body of spec §23/§38. Clients branch on Code; the reason
// travels in Details["reason"]. Details never carries secrets.
type Error struct {
	Code          smerr.Code     `json:"code"`
	Message       string         `json:"message"`
	CorrelationID string         `json:"correlation_id"`
	Details       map[string]any `json:"details"`
}

// DetailReason is the Details key holding the reason enum (spec §38).
const DetailReason = "reason"

// Reason returns Details["reason"], or "" when absent.
func (e Error) Reason() smerr.Reason {
	reason, _ := e.Details[DetailReason].(string)
	return smerr.Reason(reason)
}

// Err converts the body back into the typed error clients branch on.
func (e Error) Err() *smerr.Error {
	return &smerr.Error{Code: e.Code, Reason: e.Reason(), Message: e.Message, Details: e.Details}
}

// Page is one page of a list. NextCursor is opaque; "" means the last page.
type Page[T any] struct {
	Items      []T    `json:"items"`
	NextCursor string `json:"next_cursor"`
}

// Direct is the result of a `direct` action (spec §11.2): Applied when it ran
// inside the request transaction, Pending when policy required approval and it
// became a control_plane.apply job. Exactly one is non-nil.
type Direct[T any] struct {
	Applied *T          `json:"applied"`
	Pending *Submission `json:"pending"`
}
