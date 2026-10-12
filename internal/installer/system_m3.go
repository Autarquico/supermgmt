package installer

import (
	"context"
	"errors"
	"time"
)

// errNotImplemented marks the M3 seams frozen in W0 whose real implementation
// lands with their tasks (T5: files and services; T6 uses them).
var errNotImplemented = errors.New("installer: not implemented yet")

func (osFiles) AppendSync(string, []byte) error { return errNotImplemented }
func (osFiles) SyncDir(string) error            { return errNotImplemented }
func (osFiles) Rename(string, string) error     { return errNotImplemented }
func (osFiles) Link(string, string) error       { return errNotImplemented }
func (osFiles) Hash(string) (string, error)     { return "", errNotImplemented }

func (systemd) Load(context.Context, Unit) error    { return errNotImplemented }
func (systemd) Stop(context.Context, Unit) error    { return errNotImplemented }
func (systemd) Disable(context.Context, Unit) error { return errNotImplemented }
func (systemd) WaitStopped(context.Context, Unit, time.Duration) error {
	return errNotImplemented
}

func (launchd) Load(context.Context, Unit) error    { return errNotImplemented }
func (launchd) Stop(context.Context, Unit) error    { return errNotImplemented }
func (launchd) Disable(context.Context, Unit) error { return errNotImplemented }
func (launchd) WaitStopped(context.Context, Unit, time.Duration) error {
	return errNotImplemented
}
