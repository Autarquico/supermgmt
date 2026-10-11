// Package join is the node side of enrollment (spec §13, ADR-0022): it reads
// the node's SSH host key, asks the server to enroll the node with a join
// token, and then makes the dedicated account ready for the server's key.
// Every step converges, so running join again after a failure is safe.
package join

import (
	"context"
	"fmt"
	"strings"

	cryptossh "golang.org/x/crypto/ssh"

	"github.com/autarquico/supermgmt/internal/api/wire"
	smerr "github.com/autarquico/supermgmt/internal/errors"
)

// Enroller asks the server to enroll this node.
type Enroller interface {
	Enroll(ctx context.Context, r wire.EnrollRequest) (wire.Enrolled, error)
}

// Request is what the operator gives `sm join`.
type Request struct {
	Token string
	// Hostname overrides the machine's own hostname when it is not a valid
	// node name.
	Hostname string
	SSHPort  int
}

// Joiner runs the join steps with its collaborators.
type Joiner struct {
	Host     Host
	Enroller Enroller
}

// hostKeyFiles are tried in order of preference (ADR-0022).
var hostKeyFiles = []string{
	"/etc/ssh/ssh_host_ed25519_key.pub",
	"/etc/ssh/ssh_host_ecdsa_key.pub",
	"/etc/ssh/ssh_host_rsa_key.pub",
}

// Run joins the node. Everything that can fail locally is checked before the
// token is presented, so a node that cannot finish joining never uses a slot.
func (j Joiner) Run(ctx context.Context, r Request) (wire.Enrolled, error) {
	if strings.TrimSpace(r.Token) == "" {
		return wire.Enrolled{}, smerr.New(smerr.CodeInvalidArgument, "", "the join token is empty")
	}
	if err := j.Host.Preflight(); err != nil {
		return wire.Enrolled{}, err
	}
	hostKey, err := j.hostKey()
	if err != nil {
		return wire.Enrolled{}, err
	}
	hostname := r.Hostname
	if hostname == "" {
		if hostname, err = j.Host.Hostname(); err != nil {
			return wire.Enrolled{}, fmt.Errorf("read the hostname: %w", err)
		}
	}
	enrolled, err := j.Enroller.Enroll(ctx, wire.EnrollRequest{
		Token: strings.TrimSpace(r.Token), HostPublicKey: hostKey, Hostname: hostname,
		Addresses: j.Host.Addresses(), SSHPort: r.SSHPort,
	})
	if err != nil {
		return wire.Enrolled{}, err
	}
	return enrolled, Provision(ctx, j.Host, enrolled)
}

// hostKey returns the node's host public key as one "type base64" line, the
// form the server pins and digests.
func (j Joiner) hostKey() (string, error) {
	for _, path := range hostKeyFiles {
		raw, err := j.Host.ReadFile(path)
		if err != nil {
			continue
		}
		key, _, _, _, err := cryptossh.ParseAuthorizedKey(raw)
		if err != nil {
			return "", smerr.New(smerr.CodeCapabilityUnavailable, "", fmt.Sprintf("%s is not an OpenSSH public key", path))
		}
		return strings.TrimSpace(string(cryptossh.MarshalAuthorizedKey(key))), nil
	}
	return "", smerr.New(smerr.CodeCapabilityUnavailable, "", "no SSH host key found in /etc/ssh (is sshd installed and has it run once?)")
}
