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
		out, err := call(r.Context(), scopeOf(r.Context()).caller, in)
		if err != nil {
			return err
		}
		s.writeData(w, r, http.StatusOK, out)
		return nil
	}
}

// keyedRequest is a request whose Idempotency-Key the application honors: by
// carries it, and stored is set when the application stores the first answer
// in the mutation's transaction.
type keyedRequest struct {
	by     app.Caller
	stored *answer
}

// keyed prepares the caller of a request that must carry an Idempotency-Key.
// render turns the result the application commits into the status and wire
// value that are stored and replayed; a status of 500 or more means render
// did not recognize the result.
func keyed(r *http.Request, in input, render func(result any) (int, any)) (*keyedRequest, error) {
	key, err := in.idempotencyKey()
	if err != nil {
		return nil, err
	}
	correlation := correlationOf(r)
	k := &keyedRequest{by: scopeOf(r.Context()).caller}
	k.by.Idempotency = &app.Idempotency{
		Key: key, Method: r.Method, Path: r.URL.Path, RequestHash: in.requestHash(),
		Respond: func(result any, _ error) (int, []byte) {
			status, data := render(result)
			if status >= http.StatusInternalServerError {
				return status, errorEnvelope(smerr.New(smerr.CodeInternal, "", internalMessage), correlation)
			}
			k.stored = &answer{status: status, body: envelope(data, correlation)}
			return k.stored.status, k.stored.body
		},
	}
	return k, nil
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
		k, err := keyed(r, in, func(result any) (int, any) {
			typed, ok := result.(R)
			if !ok {
				return http.StatusInternalServerError, nil
			}
			return render(typed)
		})
		if err != nil {
			return err
		}
		if _, err := call(r.Context(), k.by, in); err != nil {
			return err
		}
		if k.stored == nil {
			// The mutation ran but no idempotency record was stored with it, so a
			// retry would run it again. Never answer success for that.
			return fmt.Errorf("%s %s: the call succeeded without storing its idempotent response", r.Method, r.URL.Path)
		}
		writeBytes(w, k.stored.status, k.stored.body)
		return nil
	}
}

// operation adapts a secret.write call (ADR-0021). When policy requires
// approval, which it does by default for this high-risk action, the request
// becomes a job: that is what the application stores under the key, so a
// replay answers the same 202. When policy lets it through, the operation is
// applied at once and answers 200; nothing is stored then, and a retry would
// apply it again.
func operation[T any](s *Server, call func(ctx context.Context, by app.Caller, in input) (app.DirectResult[T], error)) endpoint {
	return func(w http.ResponseWriter, r *http.Request) error {
		in, err := readInput(r)
		if err != nil {
			return err
		}
		k, err := keyed(r, in, func(result any) (int, any) {
			sub, ok := result.(app.Submission)
			if !ok {
				return http.StatusInternalServerError, nil
			}
			pending := app.SubmissionView(sub)
			return http.StatusAccepted, wire.Direct[T]{Pending: &pending}
		})
		if err != nil {
			return err
		}
		res, err := call(r.Context(), k.by, in)
		if err != nil {
			return err
		}
		if k.stored != nil {
			writeBytes(w, k.stored.status, k.stored.body)
			return nil
		}
		status, data := direct(http.StatusOK, same[T])(res)
		s.writeData(w, r, status, data)
		return nil
	}
}
