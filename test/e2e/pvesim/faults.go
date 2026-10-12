package pvesim

import (
	"strings"
)

// Fault makes matching tool runs fail, as a broken host would: the run fails with Code (255 by
// default) and Stderr. With After the command runs first and its effect stays, as when a tool dies
// after doing the work.
type Fault struct {
	Tool     string // pct, pveum, ...
	Contains string // the arguments joined with spaces must contain this
	Times    int    // how many runs it hits; default 1
	After    bool
	Code     int
	Stderr   string

	left int
}

func (f *Fault) response() Response {
	code := f.Code
	if code == 0 {
		code = 255
	}
	return Response{Stderr: []byte(f.Stderr + "\n"), Code: code}
}

// Inject registers a fault.
func (s *Sim) Inject(f Fault) {
	if f.Times <= 0 {
		f.Times = 1
	}
	if f.Stderr == "" {
		f.Stderr = "pvesim: injected failure"
	}
	f.left = f.Times
	s.fmu.Lock()
	defer s.fmu.Unlock()
	s.faults = append(s.faults, &f)
}

// record logs the run (arguments only, never stdin) and returns the fault it hits, if any.
func (s *Sim) record(req Request) *Fault {
	line := req.Tool + " " + strings.Join(req.Args, " ")
	s.fmu.Lock()
	defer s.fmu.Unlock()
	s.calls = append(s.calls, line)
	for _, f := range s.faults {
		if f.left > 0 && f.Tool == req.Tool && strings.Contains(line, f.Contains) {
			f.left--
			return f
		}
	}
	return nil
}

// Calls lists every tool run so far as "tool arguments", in order.
func (s *Sim) Calls() []string {
	s.fmu.Lock()
	defer s.fmu.Unlock()
	return append([]string(nil), s.calls...)
}

func (s *Sim) noteSecret(user, id, secret string) {
	s.fmu.Lock()
	defer s.fmu.Unlock()
	s.secrets = append(s.secrets, secret, user+"!"+id+"="+secret)
}

// TokenSecrets are the secrets minted so far, bare and in the user!id=secret form of the
// Authorization header.
func (s *Sim) TokenSecrets() []string {
	s.fmu.Lock()
	defer s.fmu.Unlock()
	return append([]string(nil), s.secrets...)
}
