//go:build darwin || linux

package assistant

import (
	"os/exec"
	"syscall"
)

// ownGroup puts the child in a process group of its own, so a Ctrl-C at the
// terminal (or in a program sm hands the terminal to) does not reach it, and
// so that killing it kills what it started.
func ownGroup(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error { return killGroup(cmd) }
}

// killGroup kills the child and its descendants that stayed in its group.
func killGroup(cmd *exec.Cmd) error {
	if err := syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL); err != nil {
		return cmd.Process.Kill()
	}
	return nil
}
