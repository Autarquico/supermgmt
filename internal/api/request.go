package api

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"

	"github.com/autarquico/supermgmt/internal/api/wire"
	"github.com/autarquico/supermgmt/internal/app"
	"github.com/autarquico/supermgmt/internal/domain"
	smerr "github.com/autarquico/supermgmt/internal/errors"
)

const maxIdempotencyKeyBytes = 255

func invalid(format string, args ...any) error {
	return smerr.New(smerr.CodeInvalidArgument, "", fmt.Sprintf(format, args...))
}

// input is a request after its body was read in full: the raw bytes are what
// the idempotency identity covers, and what decode parses.
type input struct {
	r    *http.Request
	body []byte
}

func readInput(r *http.Request) (input, error) {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		var tooLarge *http.MaxBytesError
		if errors.As(err, &tooLarge) {
			return input{}, invalid("request body is larger than %d bytes", tooLarge.Limit)
		}
		return input{}, invalid("cannot read the request body")
	}
	return input{r: r, body: body}, nil
}

// id is the path wildcard name as a domain.ID.
func (in input) id(name string) (domain.ID, error) {
	id, err := domain.ParseID(in.r.PathValue(name))
	if err != nil {
		return "", invalid("%s in the path is not an id", name)
	}
	return id, nil
}

// decode parses the body strictly: unknown fields and trailing data are
// refused, since a typo must not silently become a default.
func decode[T any](in input) (T, error) {
	var v T
	if len(bytes.TrimSpace(in.body)) == 0 {
		return v, invalid("a JSON request body is required")
	}
	dec := json.NewDecoder(bytes.NewReader(in.body))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&v); err != nil {
		return v, invalid("malformed request body: %s", err)
	}
	if dec.More() {
		return v, invalid("malformed request body: unexpected data after the JSON value")
	}
	return v, nil
}

// ifMatch is the spec_revision the caller read (If-Match: 3 or "3").
func (in input) ifMatch() (int64, error) {
	raw := strings.Trim(strings.TrimSpace(in.r.Header.Get(wire.HeaderIfMatch)), `"`)
	if raw == "" {
		return 0, invalid("%s is required: send the spec_revision you read", wire.HeaderIfMatch)
	}
	revision, err := strconv.ParseInt(raw, 10, 64)
	if err != nil || revision < 1 {
		return 0, invalid("%s must be a spec_revision", wire.HeaderIfMatch)
	}
	return revision, nil
}

func (in input) idempotencyKey() (string, error) {
	key := in.r.Header.Get(wire.HeaderIdempotencyKey)
	switch {
	case key == "":
		return "", invalid("%s is required on this request", wire.HeaderIdempotencyKey)
	case len(key) > maxIdempotencyKeyBytes:
		return "", invalid("%s is longer than %d bytes", wire.HeaderIdempotencyKey, maxIdempotencyKeyBytes)
	}
	for _, c := range key {
		if c < 0x21 || c > 0x7e {
			return "", invalid("%s must be printable ASCII without spaces", wire.HeaderIdempotencyKey)
		}
	}
	return key, nil
}

// requestHash is the identity of a request (ADR-0014):
// SHA-256(method, route pattern, concrete path, If-Match, raw body), each part
// length-prefixed so that no two requests share a byte stream.
func (in input) requestHash() string {
	h := sha256.New()
	for _, part := range []string{
		in.r.Method, in.r.Pattern, in.r.URL.RequestURI(), in.r.Header.Get(wire.HeaderIfMatch), string(in.body),
	} {
		_, _ = fmt.Fprintf(h, "%d:%s", len(part), part)
	}
	return hex.EncodeToString(h.Sum(nil))
}

// answer is what a Responder produced for the first execution of a request.
type answer struct {
	status int
	body   []byte
}

// reading adapts a call that answers with the wire value itself.
func reading[R any](s *Server, call func(ctx context.Context, by app.Caller, in input) (R, error)) endpoint {
	return func(w http.ResponseWriter, r *http.Request) error {
		in, err := readInput(r)
		if err != nil {
			return err
		}
		out, err := call(r.Context(), s.caller, in)
		if err != nil {
			return err
		}
		s.writeData(w, r, http.StatusOK, out)
		return nil
	}
}

// mutation adapts a call that changes state. The request must carry an
// Idempotency-Key; render turns the call's result into the HTTP status and the
// wire value, and the same bytes are stored with the mutation and sent back.
func mutation[R any](s *Server, call func(ctx context.Context, by app.Caller, in input) (R, error), render func(R) (int, any)) endpoint {
	return func(w http.ResponseWriter, r *http.Request) error {
		in, err := readInput(r)
		if err != nil {
			return err
		}
		key, err := in.idempotencyKey()
		if err != nil {
			return err
		}
		correlation := correlationOf(r)
		var first *answer
		by := s.caller
		by.Idempotency = &app.Idempotency{
			Key: key, Method: r.Method, Path: r.URL.Path, RequestHash: in.requestHash(),
			Respond: func(result any, _ error) (int, []byte) {
				typed, ok := result.(R)
				if !ok {
					return http.StatusInternalServerError, errorEnvelope(smerr.New(smerr.CodeInternal, "", internalMessage), correlation)
				}
				status, data := render(typed)
				first = &answer{status: status, body: envelope(data, correlation)}
				return first.status, first.body
			},
		}
		if _, err := call(r.Context(), by, in); err != nil {
			return err
		}
		if first == nil {
			// The mutation ran but no idempotency record was stored with it, so a
			// retry would run it again. Never answer success for that.
			return fmt.Errorf("%s %s: the call succeeded without storing its idempotent response", r.Method, r.URL.Path)
		}
		writeBytes(w, first.status, first.body)
		return nil
	}
}
