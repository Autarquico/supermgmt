//go:build darwin || linux

package cli

import "golang.org/x/sys/unix"

// disableEcho turns terminal echo off on fd and returns the function that
// restores the previous settings.
func disableEcho(fd int) (restore func(), err error) {
	saved, err := unix.IoctlGetTermios(fd, ioctlReadTermios)
	if err != nil {
		return nil, err
	}
	quiet := *saved
	quiet.Lflag &^= unix.ECHO
	if err := unix.IoctlSetTermios(fd, ioctlWriteTermios, &quiet); err != nil {
		return nil, err
	}
	return func() { _ = unix.IoctlSetTermios(fd, ioctlWriteTermios, saved) }, nil
}
