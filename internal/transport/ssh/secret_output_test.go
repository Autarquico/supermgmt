package ssh

import (
	"context"
	"strings"
	"testing"

	"github.com/autarquico/supermgmt/internal/transport/ssh/templates"
)

func TestSecretOutputIsHandedBackOnSuccessAndNeverItsStderr(t *testing.T) {
	r := newRig(t, defaultConfig(), func(s *testServer) {
		s.handler = func(string, []byte) reply { return reply{stdout: "SECRET-OUT", stderr: "SECRET-ERR"} }
	})
	res, err := r.pool.For(r.target()).Run(context.Background(), templates.Command{Line: "x", SecretOutput: true, MaxBytes: 100})
	if err != nil || string(res.Stdout) != "SECRET-OUT" || len(res.Stderr) != 0 {
		t.Fatalf("result = %+v, err = %v", res, err)
	}
}

func TestSecretOutputOfAFailedCommandIsDropped(t *testing.T) {
	r := newRig(t, defaultConfig(), func(s *testServer) {
		s.handler = func(string, []byte) reply { return reply{stdout: "SECRET-OUT", stderr: "SECRET-ERR", status: 3} }
	})
	res, err := r.pool.For(r.target()).Run(context.Background(), templates.Command{Line: "x", SecretOutput: true, MaxBytes: 100})
	if err != nil || res.ExitStatus != 3 {
		t.Fatalf("result = %+v, err = %v", res, err)
	}
	if got := string(res.Stdout) + string(res.Stderr); strings.Contains(got, "SECRET") {
		t.Errorf("a failed secret-output command returned %q", got)
	}
}
