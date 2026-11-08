//go:build darwin || linux

package cli

import (
	"io"
	"os"

	"golang.org/x/sys/unix"
)

// terminalWidth is the column count of w when it is a terminal, else 0.
func terminalWidth(w io.Writer) int {
	f, ok := w.(*os.File)
	if !ok {
		return 0
	}
	size, err := unix.IoctlGetWinsize(int(f.Fd()), unix.TIOCGWINSZ)
	if err != nil {
		return 0
	}
	return int(size.Col)
}
