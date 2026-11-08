package cli

import "golang.org/x/sys/unix"

// flushTerminalInput drops what was typed on fd and not yet read.
func flushTerminalInput(fd int) {
	const tciflush = 0 // the queue to flush: input
	_ = unix.IoctlSetInt(fd, unix.TCFLSH, tciflush)
}
