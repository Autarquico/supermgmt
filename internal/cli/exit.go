package cli

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"

	"github.com/autarquico/supermgmt/internal/database"
	smerr "github.com/autarquico/supermgmt/internal/errors"
)

// Process exit codes (spec §3.7). Codes 5 to 10 belong to the installer.
const (
	exitOK           = 0
	exitInternal     = 1
	exitUsage        = 2
	exitUnsupported  = 3
	exitPrerequisite = 4
)

// usageErrorf marks invalid arguments, flags or configuration.
func usageErrorf(format string, args ...any) error {
	return smerr.New(smerr.CodeInvalidArgument, "", fmt.Sprintf(format, args...))
}

// exitCode maps an error to the process exit code. A database that is locked
// or newer than this binary is a failed prerequisite of an offline command.
func exitCode(err error) int {
	var lockHeld *database.LockHeldError
	var tooNew *database.SchemaTooNewError
	switch {
	case err == nil:
		return exitOK
	case errors.As(err, &lockHeld), errors.As(err, &tooNew):
		return exitPrerequisite
	}
	switch smerr.CodeOf(err) { //nolint:exhaustive // every other code is a generic failure
	case smerr.CodeInvalidArgument:
		return exitUsage
	case smerr.CodeCapabilityUnavailable:
		return exitUnsupported
	default:
		return exitInternal
	}
}

type jsonError struct {
	Error jsonErrorBody `json:"error"`
}

type jsonErrorBody struct {
	Code    string         `json:"code"`
	Message string         `json:"message"`
	Reason  string         `json:"reason,omitempty"`
	Details map[string]any `json:"details,omitempty"`
}

func newJSONError(err error) jsonError {
	body := jsonErrorBody{Code: string(smerr.CodeOf(err)), Message: errorMessage(err)}
	var typed *smerr.Error
	if errors.As(err, &typed) {
		body.Reason = string(typed.Reason)
		body.Details = typed.Details
	}
	return jsonError{body}
}

// errorMessage drops the "CODE/REASON:" head of a typed error that is not
// wrapped further, since the code and reason are reported separately.
func errorMessage(err error) string {
	typed, ok := err.(*smerr.Error) //nolint:errorlint // only an unwrapped typed error is simplified
	if !ok {
		return err.Error()
	}
	switch {
	case typed.Message != "" && typed.Err != nil:
		return fmt.Sprintf("%s: %v", typed.Message, typed.Err)
	case typed.Message != "":
		return typed.Message
	}
	return err.Error()
}

func reportError(w io.Writer, err error, asJSON bool) {
	if asJSON {
		_ = json.NewEncoder(w).Encode(newJSONError(err))
		return
	}
	_, _ = fmt.Fprintf(w, "error: %s\n", errorMessage(err))
}
