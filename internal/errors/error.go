package errors

import (
	stderrors "errors"
	"fmt"
)

// Error is the typed SuperMgmt error. Code is what clients branch on; Reason
// refines it; Details carries safe, structured context (never secrets).
type Error struct {
	Code    Code
	Reason  Reason
	Message string
	Details map[string]any
	Err     error
}

// New builds an Error from explicit parts.
func New(code Code, reason Reason, msg string) *Error {
	return &Error{Code: code, Reason: reason, Message: msg}
}

// Wrap builds an Error that wraps err.
func Wrap(err error, code Code, reason Reason, msg string) *Error {
	return &Error{Code: code, Reason: reason, Message: msg, Err: err}
}

// FromReason builds an Error whose code is derived from the reason.
func FromReason(reason Reason, msg string) *Error {
	return New(CodeFor(reason), reason, msg)
}

func (e *Error) Error() string {
	head := string(e.Code)
	if e.Reason != "" {
		head += "/" + string(e.Reason)
	}
	switch {
	case e.Message != "" && e.Err != nil:
		return fmt.Sprintf("%s: %s: %v", head, e.Message, e.Err)
	case e.Message != "":
		return head + ": " + e.Message
	case e.Err != nil:
		return fmt.Sprintf("%s: %v", head, e.Err)
	}
	return head
}

func (e *Error) Unwrap() error { return e.Err }

// Is matches another *Error with the same Code and, when the target names a
// Reason, the same Reason.
func (e *Error) Is(target error) bool {
	t, ok := target.(*Error)
	if !ok {
		return false
	}
	return e.Code == t.Code && (t.Reason == "" || e.Reason == t.Reason)
}

// CodeOf returns the Code of the first *Error in err's chain, or CodeInternal.
func CodeOf(err error) Code {
	var e *Error
	if stderrors.As(err, &e) {
		return e.Code
	}
	return CodeInternal
}
