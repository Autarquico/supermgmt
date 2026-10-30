package transport

import (
	"testing"

	"github.com/autarquico/supermgmt/internal/transport/ssh/templates"
)

func TestWithhold(t *testing.T) {
	full := Result{Stdout: []byte("out"), Stderr: []byte("err"), Truncated: true}
	failed := full
	failed.ExitStatus = 1
	tests := []struct {
		name               string
		secret             bool
		in                 Result
		wantOut, wantError string
	}{
		{"ordinary command is untouched", false, failed, "out", "err"},
		{"secret output on success keeps stdout only", true, full, "out", ""},
		{"secret output on failure keeps nothing", true, failed, "", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := Withhold(templates.Command{SecretOutput: tt.secret}, tt.in)
			if string(got.Stdout) != tt.wantOut || string(got.Stderr) != tt.wantError || got.ExitStatus != tt.in.ExitStatus || got.Truncated != tt.in.Truncated {
				t.Errorf("got %+v", got)
			}
		})
	}
}
