package ssh

import (
	"context"
	"errors"
	"os"

	smerr "github.com/autarquico/supermgmt/internal/errors"
)

// carrierFailure marks an error as "the cloudflare carrier could not carry the
// stream": cloudflared died or closed before the node spoke, or the control
// plane could not reach the Access endpoint at all. It is the only evidence a
// caller may use to reach the node another way; the code of the surrounding
// smerr error (CodeNodeUnreachable is shared with an Access refusal, an
// authentication failure and a timeout) is not.
type carrierFailure struct{ cause error }

func (e carrierFailure) Error() string { return "cloudflare carrier failed: " + e.cause.Error() }
func (e carrierFailure) Unwrap() error { return e.cause }

// CarrierFailure marks cause as a carrier failure. Only the cloudflare dialler
// and tests of its callers construct one.
func CarrierFailure(cause error) error { return carrierFailure{cause: cause} }

// authRejected marks an error as "the node answered and refused every offered
// key". Its code stays CodeNodeUnreachable, which says nothing about whether
// the node was reached.
type authRejected struct{ cause error }

func (e authRejected) Error() string { return e.cause.Error() }
func (e authRejected) Unwrap() error { return e.cause }

// AuthRejected marks cause as a refusal of the offered keys. Only the
// handshake classifier and tests of its callers construct one.
func AuthRejected(cause error) error { return authRejected{cause: cause} }

// IsAuthRejected reports whether err says the node refused the offered keys.
func IsAuthRejected(err error) bool {
	var marked authRejected
	return errors.As(err, &marked)
}

// IsCarrierFailure reports whether err says the cloudflare carrier could not
// carry the stream to the node. It is false for an Access refusal, an SSH
// authentication failure, a host-key mismatch, a cancelled or timed out
// attempt and a missing or untrusted cloudflared.
func IsCarrierFailure(err error) bool {
	var marked carrierFailure
	if !errors.As(err, &marked) || smerr.CodeOf(err) != smerr.CodeNodeUnreachable {
		return false
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) || errors.Is(err, os.ErrClosed) || errors.Is(err, os.ErrDeadlineExceeded) {
		return false
	}
	return true
}
