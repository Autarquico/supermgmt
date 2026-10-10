package cli

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
)

const (
	exitOK       = 0
	exitInternal = 1
	exitUsage    = 2
)

// usageError marks invalid arguments, flags or configuration (exit code 2).
type usageError struct{ msg string }

func (e *usageError) Error() string { return e.msg }

func usageErrorf(format string, args ...any) error {
	return &usageError{msg: fmt.Sprintf(format, args...)}
}

// exitCode maps an error to the process exit code.
func exitCode(err error) int {
	var usage *usageError
	switch {
	case err == nil:
		return exitOK
	case errors.As(err, &usage):
		return exitUsage
	default:
		return exitInternal
	}
}

// errorCode is the machine-readable code reported with --json.
func errorCode(err error) string {
	if exitCode(err) == exitUsage {
		return "INVALID_ARGUMENT"
	}
	return "INTERNAL"
}

type jsonError struct {
	Error jsonErrorBody `json:"error"`
}

type jsonErrorBody struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

func reportError(w io.Writer, err error, asJSON bool) {
	if asJSON {
		_ = json.NewEncoder(w).Encode(jsonError{jsonErrorBody{errorCode(err), err.Error()}})
		return
	}
	_, _ = fmt.Fprintf(w, "error: %s\n", err)
}
