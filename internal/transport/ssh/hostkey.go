package ssh

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	cryptossh "golang.org/x/crypto/ssh"

	smerr "github.com/autarquico/supermgmt/internal/errors"
)

// scanTimeout bounds a keyscan that the caller's context does not bound.
const scanTimeout = 10 * time.Second

// HostKey is a scanned server key, shown to the user for confirmation (spec §12).
type HostKey struct {
	Authorized        string // authorized_keys form, no comment: the value pinned in the database
	Type              string
	FingerprintSHA256 string
}

var errScanDone = errors.New("host key captured")

// scanAlgorithms fixes the preference so a scan is deterministic across servers.
var scanAlgorithms = []string{
	cryptossh.KeyAlgoED25519, cryptossh.KeyAlgoECDSA256, cryptossh.KeyAlgoECDSA384, cryptossh.KeyAlgoECDSA521,
	cryptossh.KeyAlgoRSASHA512, cryptossh.KeyAlgoRSASHA256,
}

// ScanHostKey reads the key a server presents without authenticating: the
// handshake is aborted the moment the key is seen. The result is only
// information until a human confirms the fingerprint.
func ScanHostKey(ctx context.Context, host string, port int) (HostKey, error) {
	if err := validateEndpoint(host, port); err != nil {
		return HostKey{}, err
	}
	ctx, cancel := context.WithTimeout(ctx, scanTimeout)
	defer cancel()

	var seen cryptossh.PublicKey
	cfg := &cryptossh.ClientConfig{
		User:              "supermgmt-scan",
		HostKeyAlgorithms: scanAlgorithms,
		HostKeyCallback: func(_ string, _ net.Addr, key cryptossh.PublicKey) error {
			seen = key
			return errScanDone
		},
	}
	conn, err := (&net.Dialer{}).DialContext(ctx, "tcp", net.JoinHostPort(host, strconv.Itoa(port)))
	if err != nil {
		return HostKey{}, unreachable("scan host key", err)
	}
	defer conn.Close()
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stop()

	_, _, _, err = cryptossh.NewClientConn(conn, net.JoinHostPort(host, strconv.Itoa(port)), cfg)
	if seen == nil {
		if ctx.Err() != nil {
			return HostKey{}, ctxError("scan host key", ctx.Err())
		}
		return HostKey{}, unreachable("scan host key", err)
	}
	return HostKey{
		Authorized:        strings.TrimSpace(string(cryptossh.MarshalAuthorizedKey(seen))),
		Type:              seen.Type(),
		FingerprintSHA256: cryptossh.FingerprintSHA256(seen),
	}, nil
}

func validateEndpoint(host string, port int) error {
	switch {
	case host == "" || strings.HasPrefix(host, "-") || strings.ContainsAny(host, " \t\r\n\x00/@"):
		return smerr.New(smerr.CodeInvalidArgument, "", "invalid ssh host")
	case port < 1 || port > 65535:
		return smerr.New(smerr.CodeInvalidArgument, "", "invalid ssh port")
	}
	return nil
}

// pinnedKey is the database-pinned server key (spec §6.4) in authorized_keys form.
type pinnedKey struct{ key cryptossh.PublicKey }

func parsePinned(authorized string) (pinnedKey, error) {
	key, _, _, rest, err := cryptossh.ParseAuthorizedKey([]byte(authorized))
	if err != nil || len(bytes.TrimSpace(rest)) != 0 {
		return pinnedKey{}, smerr.New(smerr.CodeInvalidArgument, "", "pinned host key is not a single authorized_keys entry")
	}
	if _, isCert := key.(*cryptossh.Certificate); isCert {
		return pinnedKey{}, smerr.New(smerr.CodeInvalidArgument, "", "certificate host keys are not supported")
	}
	return pinnedKey{key: key}, nil
}

// algorithms restricts negotiation to the pinned key's type, so a server that
// also holds other key types still presents the pinned one.
func (p pinnedKey) algorithms() []string {
	if p.key.Type() == cryptossh.KeyAlgoRSA {
		return []string{cryptossh.KeyAlgoRSASHA512, cryptossh.KeyAlgoRSASHA256}
	}
	return []string{p.key.Type()}
}

// hostKeyMismatch records that the server presented some other key.
type hostKeyMismatch struct{ presented, pinned string }

// Error names both fingerprints, so an operator can tell a changed key from a
// wrong pin.
func (e *hostKeyMismatch) Error() string {
	return "the server presented host key " + e.presented + " but the pinned key is " + e.pinned
}

// callback compares exact key bytes; nothing but the pinned key is trusted.
func (p pinnedKey) callback(mismatch **hostKeyMismatch) cryptossh.HostKeyCallback {
	return func(_ string, _ net.Addr, key cryptossh.PublicKey) error {
		if bytes.Equal(key.Marshal(), p.key.Marshal()) {
			return nil
		}
		*mismatch = &hostKeyMismatch{presented: cryptossh.FingerprintSHA256(key), pinned: cryptossh.FingerprintSHA256(p.key)}
		return *mismatch
	}
}

func unreachable(what string, err error) error {
	if cause := networkCause(err); cause != "" {
		what += ": " + cause
	}
	return smerr.Wrap(err, smerr.CodeNodeUnreachable, "", what)
}

// networkCause names why a node could not be reached ("connect: no route to
// host", "lookup web1: no such host") without the local addresses or the
// resolver that the full error carries.
func networkCause(err error) string {
	var dnsErr *net.DNSError
	if errors.As(err, &dnsErr) {
		return "lookup " + dnsErr.Name + ": " + dnsErr.Err
	}
	var opErr *net.OpError
	if errors.As(err, &opErr) && opErr.Err != nil {
		return opErr.Err.Error()
	}
	return ""
}

func ctxError(what string, err error) error {
	if errors.Is(err, context.DeadlineExceeded) {
		return smerr.Wrap(err, smerr.CodeTimeout, "", what+": deadline exceeded")
	}
	return fmt.Errorf("%s: %w", what, err)
}
