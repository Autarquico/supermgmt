package app

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/autarquico/supermgmt/internal/audit"
	"github.com/autarquico/supermgmt/internal/database"
	"github.com/autarquico/supermgmt/internal/domain"
	smerr "github.com/autarquico/supermgmt/internal/errors"
	"github.com/autarquico/supermgmt/internal/jobs"
	"github.com/autarquico/supermgmt/internal/providers/proxmox"
	"github.com/autarquico/supermgmt/internal/runtimes"
	"github.com/autarquico/supermgmt/internal/runtimes/systemd"
	"github.com/autarquico/supermgmt/internal/secrets"
	"github.com/autarquico/supermgmt/internal/textsafe"
)

// The event names describe a token; they are not credentials.
//
//nolint:gosec // G101: event names, not credentials
const (
	eventProxmoxTokenCreated = "node.proxmox.token_created"
	eventProxmoxTokenDeleted = "node.proxmox.token_deleted"

	// proxmoxProofTimeout bounds the whole proof: the handshake and the GET /version.
	proxmoxProofTimeout = time.Minute
	maxSANsShown        = 20
)

var proxmoxSecretNodePattern = regexp.MustCompile(`^[a-z0-9][a-z0-9-]*$`)

// proxmoxSecretName is where the node's PVE token lives in the secret store.
// The store only has lower-case names, so a node name that is not would share a
// slot with another one; it is refused instead.
func proxmoxSecretName(node string) (string, error) {
	if !proxmoxSecretNodePattern.MatchString(node) {
		return "", smerr.New(smerr.CodeInvalidArgument, "", "--proxmox needs a node name of lower-case letters, digits and dashes: its token is stored as secret://proxmox/<node>")
	}
	return "proxmox/" + node, nil
}

// proxmoxParams builds the Proxmox step of node.setup: the token's secret goes
// to the store the moment pveum prints it, and both the creation and the deletion
// of a token are audited by its public id.
func (h setupHandler) proxmoxParams(ctx context.Context, lease jobs.Lease, job jobs.Job, node domain.Node, instanceID string) (*systemd.ProxmoxParams, error) {
	if h.secrets == nil {
		return nil, smerr.New(smerr.CodeCapabilityUnavailable, "", "no secret store is configured for --proxmox")
	}
	name, err := proxmoxSecretName(node.Name)
	if err != nil {
		return nil, err
	}
	stored, err := h.tokenStored(ctx, name)
	if err != nil {
		return nil, err
	}
	ownedRoles, err := roleJournal(ctx, h.cfg.DB.Reader(), node.ID)
	if err != nil {
		return nil, err
	}
	return &systemd.ProxmoxParams{
		InstanceID: instanceID, TokenStored: stored, OwnedRoles: ownedRoles,
		StoreToken: func(ctx context.Context, tokenID string, secret audit.Secret) error {
			value := audit.Secret(tokenID + "=" + secret.Reveal())
			if _, err := h.secrets.Put(ctx, name, value, map[string]any{"node": node.Name, "pve_id": tokenID}); err != nil {
				return err
			}
			return h.tokenEvent(ctx, lease, job, node, eventProxmoxTokenCreated, tokenID)
		},
		TokenRemoved: func(ctx context.Context, tokenID string) error {
			return h.tokenEvent(ctx, lease, job, node, eventProxmoxTokenDeleted, tokenID)
		},
		RoleOwned: func(ctx context.Context, role string) error {
			return h.journalRole(ctx, lease, node, role)
		},
	}, nil
}

// roleJournal is the roles setup journaled as created on the node; none when
// no row exists.
func roleJournal(ctx context.Context, q database.Querier, node domain.ID) ([]string, error) {
	c, err := database.GetNodeCapability(ctx, q, node, capabilityProxmoxRoles)
	if smerr.CodeOf(err) == smerr.CodeNotFound {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	raw, _ := c.Metadata["roles"].([]any)
	roles := make([]string, 0, len(raw))
	for _, r := range raw {
		name, ok := r.(string)
		if !ok {
			return nil, smerr.New(smerr.CodeInternal, "", "the Proxmox role journal is malformed")
		}
		roles = append(roles, name)
	}
	return roles, nil
}

// journalRole adds role to the node's journal, fenced by the job's lease. It
// runs before the role is created, so a run that fails afterwards still owns it.
func (h setupHandler) journalRole(ctx context.Context, lease jobs.Lease, node domain.Node, role string) error {
	return h.write(ctx, func(ctx context.Context, tx *database.Tx) error {
		if err := lease.Fence(ctx, tx); err != nil {
			return err
		}
		roles, err := roleJournal(ctx, tx, node.ID)
		if err != nil {
			return err
		}
		roles = slices.Compact(slices.Sorted(slices.Values(append(roles, role))))
		return database.SetNodeCapability(ctx, tx, node.ID, database.NodeCapability{
			Capability: capabilityProxmoxRoles, Available: true,
			Metadata: map[string]any{"roles": roles}, CheckedAt: h.cfg.Clock.Now(),
		})
	})
}

func (h setupHandler) tokenStored(ctx context.Context, name string) (bool, error) {
	_, err := h.secrets.Get(ctx, secrets.Ref{Name: name})
	switch {
	case err == nil:
		return true, nil
	case smerr.CodeOf(err) == smerr.CodeNotFound:
		return false, nil
	}
	return false, fmt.Errorf("look up the stored Proxmox token: %w", err)
}

// tokenEvent audits a token creation or deletion, fenced by the job's lease.
// Only the public token id is recorded.
func (h setupHandler) tokenEvent(ctx context.Context, lease jobs.Lease, job jobs.Job, node domain.Node, action, tokenID string) error {
	return h.write(ctx, func(ctx context.Context, tx *database.Tx) error {
		if err := lease.Fence(ctx, tx); err != nil {
			return err
		}
		actor, err := loadActor(ctx, tx, job.ActorID, credentialOf(job))
		if err != nil {
			return err
		}
		return h.emit(ctx, tx, actor, action, nodeRef(node.ID), domain.ResultSucceeded, map[string]any{
			"pve_id": tokenID, "job_id": job.ID.String(),
		})
	})
}

// proxmoxMeta is the Proxmox state setup records: with --proxmox the one just
// proven, otherwise what the node already had (a setup without the option keeps
// it, like the tunnel).
func (h setupHandler) proxmoxMeta(ctx context.Context, node domain.Node, req setupRequest, id secrets.Identity, outcome systemd.SetupOutcome) (*runtimes.ProxmoxMeta, error) {
	if !req.Proxmox {
		previous, err := loadSetup(ctx, h.cfg.DB.Reader(), node.ID)
		if err != nil || previous == nil {
			return nil, err
		}
		return previous.ProxmoxState(), nil
	}
	if outcome.Proxmox == nil {
		return nil, smerr.New(smerr.CodeInternal, "", "node.setup --proxmox returned no Proxmox outcome")
	}
	ctx, cancel := context.WithTimeout(ctx, proxmoxProofTimeout)
	defer cancel()
	name, err := proxmoxSecretName(node.Name)
	if err != nil {
		return nil, err
	}
	px := *outcome.Proxmox
	credentialRef := pinnedIdentityRef(id)
	dial := func(ctx context.Context) (net.Conn, error) {
		return h.conn.OpenRelay(ctx, node, credentialRef, px.SocatPath)
	}
	serverName, err := discoverTLSServerName(ctx, dial, px.CAPEM, px.Hostname)
	if err != nil {
		return nil, err
	}
	if err := h.proveAPI(ctx, dial, name, px.CAPEM, serverName); err != nil {
		return nil, err
	}
	return &runtimes.ProxmoxMeta{
		CAPEM: px.CAPEM, TokenRef: "secret://" + name, TokenID: px.TokenID, TLSServerName: serverName,
		RelayPath: px.SocatPath, InstalledAt: h.cfg.Clock.Now(),
	}, nil
}

// proveAPI sends one authenticated GET /version with the stored token over a
// relay, verified against the CA and the discovered name. Nothing carrying the
// token has been sent before this.
func (h setupHandler) proveAPI(ctx context.Context, dial func(context.Context) (net.Conn, error), secretName, caPEM, serverName string) error {
	token, err := h.secrets.Get(ctx, secrets.Ref{Name: secretName})
	if err != nil {
		return fmt.Errorf("read the stored Proxmox token: %w", err)
	}
	client, err := proxmox.New("", []byte(caPEM), token, proxmox.WithDialer(dial), proxmox.WithServerName(serverName))
	if err != nil {
		return smerr.New(smerr.CodeCapabilityUnavailable, "", "cannot build the Proxmox client: "+textsafe.Line(err.Error()))
	}
	if closer, ok := client.(proxmox.IdleCloser); ok {
		defer closer.CloseIdle()
	}
	if _, err := client.Version(ctx); err != nil {
		return smerr.New(smerr.CodeCapabilityUnavailable, "",
			"the Proxmox API did not answer an authenticated GET /version through the relay: "+textsafe.Line(err.Error()))
	}
	return nil
}

// discoverTLSServerName handshakes over a relay, requires the certificate to
// chain to caPEM and picks the name the client will verify (tlsServerNameOf).
// The handshake carries no credential.
func discoverTLSServerName(ctx context.Context, dial func(context.Context) (net.Conn, error), caPEM, hostname string) (string, error) {
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM([]byte(caPEM)) {
		return "", smerr.New(smerr.CodeInternal, "", "the recorded CA is not PEM")
	}
	conn, err := dial(ctx)
	if err != nil {
		return "", fmt.Errorf("open the Proxmox relay: %w", err)
	}
	defer func() { _ = conn.Close() }()
	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	}
	var leaf *x509.Certificate
	config := &tls.Config{
		MinVersion: tls.VersionTLS12,
		// The chain is verified in VerifyConnection, without a name: the name is
		// what this handshake is for.
		InsecureSkipVerify: true, //nolint:gosec // VerifyConnection checks the chain against the CA
		VerifyConnection: func(cs tls.ConnectionState) error {
			if len(cs.PeerCertificates) == 0 {
				return fmt.Errorf("no certificate")
			}
			intermediates := x509.NewCertPool()
			for _, c := range cs.PeerCertificates[1:] {
				intermediates.AddCert(c)
			}
			leaf = cs.PeerCertificates[0]
			_, err := leaf.Verify(x509.VerifyOptions{Roots: roots, Intermediates: intermediates})
			return err
		},
	}
	if err := tls.Client(conn, config).HandshakeContext(ctx); err != nil {
		return "", smerr.New(smerr.CodeCapabilityUnavailable, "",
			"the TLS handshake with the Proxmox API failed or its certificate does not chain to the host's root CA: "+textsafe.Line(err.Error()))
	}
	return tlsServerNameOf(leaf, hostname)
}

// tlsServerNameOf is the first of localhost, 127.0.0.1 and the node's hostname
// that the leaf certificate names. None is CAPABILITY_UNAVAILABLE listing the
// names it has.
func tlsServerNameOf(leaf *x509.Certificate, hostname string) (string, error) {
	for _, candidate := range []string{"localhost", "127.0.0.1", hostname} {
		if leaf.VerifyHostname(candidate) == nil {
			return candidate, nil
		}
	}
	return "", smerr.New(smerr.CodeCapabilityUnavailable, "",
		fmt.Sprintf("the Proxmox API certificate names none of localhost, 127.0.0.1 or %s; it names: %s", textsafe.Line(hostname), namesOf(leaf)))
}

// namesOf lists a certificate's subject alternative names for a message.
func namesOf(leaf *x509.Certificate) string {
	var names []string
	names = append(names, leaf.DNSNames...)
	for _, ip := range leaf.IPAddresses {
		names = append(names, ip.String())
	}
	if len(names) == 0 {
		return "no names"
	}
	if len(names) > maxSANsShown {
		names = append(names[:maxSANsShown], "...")
	}
	for i, n := range names {
		names[i] = textsafe.Line(n)
	}
	return strings.Join(names, ", ")
}
