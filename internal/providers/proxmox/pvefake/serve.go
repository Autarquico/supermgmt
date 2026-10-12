package pvefake

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
)

const apiPrefix = "/api2/json"

type faultKind int

const (
	faultRespond faultKind = iota + 1
	faultDropBefore
	faultDropAfter
	faultHang
)

// Fault is a failure injected by Inject.
type Fault struct {
	kind faultKind
	code int
	body string
}

// Respond answers with the given status and body without running the
// request.
func Respond(code int, body string) Fault { return Fault{kind: faultRespond, code: code, body: body} }

// DropBefore closes the connection without running the request.
func DropBefore() Fault { return Fault{kind: faultDropBefore} }

// DropAfter runs the request, then closes the connection without answering:
// the client cannot tell the work was done.
func DropAfter() Fault { return Fault{kind: faultDropAfter} }

// Hang never answers until the client gives up.
func Hang() Fault { return Fault{kind: faultHang} }

// Rule applies a Fault to the next Times (default 1) requests with Method
// whose path ends in PathSuffix.
type Rule struct {
	Method     string
	PathSuffix string
	Times      int
	Fault      Fault
}

type rule struct {
	Rule
	left int
}

// Inject registers a failure rule.
func (f *Fake) Inject(r Rule) {
	if r.Times <= 0 {
		r.Times = 1
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.rules = append(f.rules, &rule{Rule: r, left: r.Times})
}

func tlsConfig(cert tls.Certificate) *tls.Config {
	return &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}
}

func (f *Fake) handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET "+apiPrefix+"/version", f.authed(f.getVersion))
	mux.HandleFunc("GET "+apiPrefix+"/cluster/resources", f.authed(f.getResources))
	mux.HandleFunc("GET "+apiPrefix+"/access/permissions", f.authed(f.getPermissions))
	mux.HandleFunc("GET "+apiPrefix+"/nodes/{node}/tasks", f.authed(f.listTasks))
	mux.HandleFunc("GET "+apiPrefix+"/nodes/{node}/tasks/{upid}/status", f.authed(f.taskStatus))
	mux.HandleFunc("POST "+apiPrefix+"/nodes/{node}/{type}/{vmid}/status/{verb}", f.authed(f.power))
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		writeError(w, http.StatusNotImplemented, fmt.Sprintf("Method '%s %s' not implemented", r.Method, r.URL.Path), nil)
	})
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fault, injected := f.record(r)
		if !injected {
			mux.ServeHTTP(w, r)
			return
		}
		switch fault.kind {
		case faultRespond:
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(fault.code)
			_, _ = w.Write([]byte(fault.body))
		case faultDropBefore:
			drop(w)
		case faultDropAfter:
			mux.ServeHTTP(httptest.NewRecorder(), r)
			drop(w)
		case faultHang:
			select {
			case <-r.Context().Done():
			case <-f.done:
			}
		}
	})
}

func drop(w http.ResponseWriter) {
	conn, _, err := w.(http.Hijacker).Hijack()
	if err == nil {
		_ = conn.Close()
	}
}

// record logs the request and returns the fault to apply, if any.
func (f *Fake) record(r *http.Request) (Fault, bool) {
	_ = r.ParseForm()
	f.mu.Lock()
	defer f.mu.Unlock()
	path := strings.TrimPrefix(r.URL.Path, apiPrefix)
	f.requests = append(f.requests, Request{Method: r.Method, Path: path, Query: r.URL.Query(), Form: r.PostForm})
	for _, ru := range f.rules {
		if ru.left > 0 && ru.Method == r.Method && strings.HasSuffix(path, ru.PathSuffix) {
			ru.left--
			return ru.Fault, true
		}
	}
	return Fault{}, false
}

// call is an authenticated request.
type call struct {
	r       *http.Request
	tokenID string
}

func (f *Fake) authed(h func(http.ResponseWriter, *call)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id, ok := f.authenticate(r.Header.Get("Authorization"))
		if !ok {
			writeError(w, http.StatusUnauthorized, "No ticket", nil)
			return
		}
		h(w, &call{r: r, tokenID: id})
	}
}

func (f *Fake) authenticate(header string) (string, bool) {
	value, ok := strings.CutPrefix(header, "PVEAPIToken=")
	if !ok {
		return "", false
	}
	id, secret, ok := strings.Cut(value, "=")
	f.mu.Lock()
	defer f.mu.Unlock()
	tok, known := f.tokens[id]
	return id, ok && known && tok.secret == secret
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

func writeData(w http.ResponseWriter, data any) { writeJSON(w, map[string]any{"data": data}) }

// writeError answers in the shape PVE uses for failures.
func writeError(w http.ResponseWriter, code int, message string, errs map[string]string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	body := map[string]any{"data": nil, "message": message + "\n"}
	if errs != nil {
		body["errors"] = errs
	}
	_ = json.NewEncoder(w).Encode(body)
}
