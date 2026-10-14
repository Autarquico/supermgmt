package api

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"

	"github.com/autarquico/supermgmt/internal/api/wire"
	"github.com/autarquico/supermgmt/internal/app"
)

// inProcessKey carries the caller of an in-process request. The type is
// unexported, so no header, URL or body of any request can set it: only
// Server.InProcess does.
type inProcessKey struct{}

func inProcessCaller(ctx context.Context) (app.Caller, bool) {
	by, ok := ctx.Value(inProcessKey{}).(app.Caller)
	return by, ok
}

// InProcess is an http.RoundTripper that runs requests through the full
// request pipeline of s, with no network, as by (ADR-0031: the remote MCP
// handler calls the API this way). The caller is the one given here, whatever
// the request says: a request that carries an Authorization header is refused,
// since it would suggest a second identity. Each write is charged once to the
// per-identity write bucket of by.
func (s *Server) InProcess(by app.Caller) http.RoundTripper { return inProcess{s: s, by: by} }

type inProcess struct {
	s  *Server
	by app.Caller
}

func (t inProcess) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.Body != nil {
		defer func() { _ = req.Body.Close() }()
	}
	if t.by.ID == "" {
		return nil, errors.New("api: an in-process request needs a caller")
	}
	if _, bearer := req.Header[wire.HeaderAuthorization]; bearer {
		return nil, errors.New("api: an in-process request carries its caller, not a token")
	}
	in := req.Clone(context.WithValue(req.Context(), inProcessKey{}, t.by))
	if in.Body == nil {
		in.Body = http.NoBody
	}
	rec := &recorder{header: http.Header{}}
	t.s.handler.ServeHTTP(rec, in)
	return rec.response(req), nil
}

// admitInProcess is the admission of an in-process request: its caller was
// stamped by InProcess, so only the limit and the credential scope apply.
func (s *Server) admitInProcess(by app.Caller, rt route) (scope, error) {
	if err := requireScope(by, rt); err != nil {
		return scope{}, err
	}
	if err := s.chargeWrite(by, rt); err != nil {
		return scope{}, err
	}
	return scope{caller: by}, nil
}

// recorder is the http.ResponseWriter of an in-process request.
type recorder struct {
	header http.Header
	status int
	body   bytes.Buffer
}

func (r *recorder) Header() http.Header { return r.header }

func (r *recorder) WriteHeader(status int) {
	if r.status == 0 {
		r.status = status
	}
}

func (r *recorder) Write(p []byte) (int, error) {
	r.WriteHeader(http.StatusOK)
	return r.body.Write(p)
}

func (r *recorder) response(req *http.Request) *http.Response {
	r.WriteHeader(http.StatusOK)
	return &http.Response{
		Status: http.StatusText(r.status), StatusCode: r.status,
		Proto: "HTTP/1.1", ProtoMajor: 1, ProtoMinor: 1,
		Header: r.header, ContentLength: int64(r.body.Len()),
		Body: io.NopCloser(&r.body), Request: req,
	}
}
