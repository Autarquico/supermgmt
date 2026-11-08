package cli

import "golang.org/x/sys/unix"

// flushTerminalInput drops what was typed on fd and not yet read.
func flushTerminalInput(fd int) {
	const fread = 0x1 // the queue to flush: input
	_ = unix.IoctlSetPointerInt(fd, unix.TIOCFLUSH, fread)
}
