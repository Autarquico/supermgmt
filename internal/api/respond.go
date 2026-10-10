package api

import (
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"

	"github.com/autarquico/supermgmt/internal/api/wire"
	"github.com/autarquico/supermgmt/internal/app"
	"github.com/autarquico/supermgmt/internal/audit"
	"github.com/autarquico/supermgmt/internal/domain"
	smerr "github.com/autarquico/supermgmt/internal/errors"
)

const internalMessage = "internal error"

// statusOf maps an error code to its HTTP status (spec §23, §38). Clients
// branch on the code; the status only helps generic HTTP tooling.
func statusOf(code smerr.Code) int {
	switch code {
	case smerr.CodeInvalidArgument:
		return http.StatusBadRequest
	case smerr.CodeNotFound:
		return http.StatusNotFound
	case smerr.CodeConflict, smerr.CodeCINotPassed:
		return http.StatusConflict
	case smerr.CodeUnauthenticated:
		return http.StatusUnauthorized
	case smerr.CodePolicyDenied, smerr.CodeApprovalRequired:
		return http.StatusForbidden
	case smerr.CodeCapabilityUnavailable, smerr.CodeArtifactNotImmutable:
		return http.StatusUnprocessableEntity
	case smerr.CodeNodeUnreachable, smerr.CodeSSHHostKeyMismatch, smerr.CodeProviderError:
		return http.StatusBadGateway
	case smerr.CodeTimeout:
		return http.StatusGatewayTimeout
	case smerr.CodeDeploymentFailed, smerr.CodeRollbackFailed, smerr.CodeInternal:
		return http.StatusInternalServerError
	}
	return http.StatusInternalServerError
}

// envelope is the exact wire encoding of a success: {"data":…,"meta":{…}}.
func envelope(data any, correlation domain.ID) []byte {
	body, err := json.Marshal(wire.Envelope[any]{Data: data, Meta: wire.Meta{CorrelationID: correlation.String()}})
	if err != nil {
		return errorEnvelope(smerr.New(smerr.CodeInternal, "", internalMessage), correlation)
	}
	return append(body, '\n')
}

// errorEnvelope encodes err for the wire.
func errorEnvelope(err *smerr.Error, correlation domain.ID) []byte {
	details := map[string]any{}
	for k, v := range err.Details {
		details[k] = v
	}
	if err.Reason != "" {
		details[wire.DetailReason] = string(err.Reason)
	}
	body, _ := json.Marshal(wire.ErrorEnvelope{Error: wire.Error{
		Code: err.Code, Message: err.Message, CorrelationID: correlation.String(), Details: details,
	}})
	return append(body, '\n')
}

// publicError is what a client may learn about err: typed errors keep their
// code, reason and message but never their wrapped cause; anything else, and
// typed internal failures, are "internal error" with the cause left in the log.
func publicError(err error) *smerr.Error {
	var typed *smerr.Error
	if errors.As(err, &typed) && typed.Code != smerr.CodeInternal {
		return &smerr.Error{Code: typed.Code, Reason: typed.Reason, Message: typed.Message, Details: typed.Details}
	}
	return smerr.New(smerr.CodeInternal, "", internalMessage)
}

func writeBytes(w http.ResponseWriter, status int, body []byte) {
	w.Header().Set("Content-Type", wire.ContentType)
	w.WriteHeader(status)
	_, _ = w.Write(body) //nolint:gosec // JSON envelope served as application/json over the owner-only Unix socket, never rendered as HTML
}

func (s *Server) writeData(w http.ResponseWriter, r *http.Request, status int, data any) {
	writeBytes(w, status, envelope(data, correlationOf(r)))
}

// writeError renders err. An *app.Replay is not a failure: it carries the
// stored answer of an earlier identical request and is written verbatim.
func (s *Server) writeError(w http.ResponseWriter, r *http.Request, err error) {
	var replay *app.Replay
	if errors.As(err, &replay) {
		w.Header().Set(wire.HeaderIdempotentReplayed, "true")
		writeBytes(w, replay.Status, replay.Envelope)
		return
	}
	public := publicError(err)
	correlation := correlationOf(r)
	if public.Code == smerr.CodeInternal {
		s.log.ErrorContext(r.Context(), "request failed", slog.String("correlation_id", correlation.String()),
			slog.String("method", r.Method), slog.String("path", r.URL.Path), slog.Any("error", err))
	}
	writeBytes(w, statusOf(public.Code), errorEnvelope(public, correlation))
}

func withCorrelation(r *http.Request, id domain.ID) *http.Request {
	return r.WithContext(audit.WithCorrelationID(r.Context(), id))
}

func correlationOf(r *http.Request) domain.ID {
	id, _ := audit.CorrelationID(r.Context())
	return id
}
