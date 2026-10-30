package app

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/autarquico/supermgmt/internal/api/wire"
	"github.com/autarquico/supermgmt/internal/config"
	"github.com/autarquico/supermgmt/internal/database"
	"github.com/autarquico/supermgmt/internal/domain"
	smerr "github.com/autarquico/supermgmt/internal/errors"
	sshnode "github.com/autarquico/supermgmt/internal/providers/ssh"
	"github.com/autarquico/supermgmt/internal/secrets"
)

const (
	actionEnrollmentCreate = "enrollment.create"

	// JoinTokenKind is the kind byte of a join token ("smj_...").
	JoinTokenKind byte = 'j'

	eventEnrollmentCreated = "enrollment.created"
	eventEnrollmentDenied  = "enrollment.denied"
	eventNodeEnrolled      = "node.enrolled"

	defaultEnrollmentTTL = time.Hour
	maxEnrollmentCIDRs   = 64
	maxEnrolledPort      = 65535

	// Metadata keys of an enrolled node: its answer, kept so a retry returns
	// the same key line even after the instance identity rotated (ADR-0022).
	metaJoinAuthorizedKey = "join_authorized_key"
	metaJoinKeyVersion    = "join_key_version"
	metaJoinKeyPrint      = "join_key_fingerprint"
)

// EnrollmentService implements Enrollments (spec §13, ADR-0022): issuing join
// tokens and turning a presented token into a pinned, managed SSH node.
type EnrollmentService struct {
	core
	tokens   TokenMinter
	identity SSHIdentity
}

var _ Enrollments = (*EnrollmentService)(nil)

// NewEnrollments validates cfg and the collaborators.
func NewEnrollments(cfg Config, tokens TokenMinter, identity SSHIdentity) (*EnrollmentService, error) {
	c, err := newCore(cfg)
	if err != nil {
		return nil, err
	}
	if tokens == nil || identity == nil {
		return nil, fmt.Errorf("app: enrollments need a token minter and the instance identity")
	}
	return &EnrollmentService{core: c, tokens: tokens, identity: identity}, nil
}

// ---- issuing --------------------------------------------------------------------

// Create issues a join token (action enrollment.create). Credential-issuing:
// it never takes an Idempotency-Key and the plaintext leaves only here.
func (e *EnrollmentService) Create(ctx context.Context, by Caller, r wire.EnrollmentRequest) (wire.EnrollmentIssued, error) {
	if by.Idempotency != nil {
		return wire.EnrollmentIssued{}, errIdempotencyKeyRefused()
	}
	now := e.cfg.Clock.Now()
	constraints, expiresAt, err := enrollmentConstraints(now, r)
	if err != nil {
		return wire.EnrollmentIssued{}, err
	}
	return commit(ctx, e.core, by, func(ctx context.Context, tx *database.Tx) (wire.EnrollmentIssued, error) {
		actor, err := e.beginRequest(ctx, tx, by)
		if err != nil {
			return wire.EnrollmentIssued{}, err
		}
		instance, err := database.GetInstance(ctx, tx)
		if err != nil {
			return wire.EnrollmentIssued{}, err
		}
		ref := domain.ResourceRef{Type: domain.ResourceInstance, ID: instance.ID}
		if err := e.requireAllowed(ctx, tx, actor, actionEnrollmentCreate, ref); err != nil {
			return wire.EnrollmentIssued{}, err
		}
		secret, hash, err := e.tokens.Mint(JoinTokenKind)
		if err != nil {
			return wire.EnrollmentIssued{}, err
		}
		token := database.JoinToken{
			ID: e.cfg.IDs.NewID(), TokenHash: hash, CreatedBy: actor.ID,
			Constraints: constraints, CreatedAt: now, ExpiresAt: expiresAt,
		}
		if err := database.CreateJoinToken(ctx, tx, token); err != nil {
			return wire.EnrollmentIssued{}, err
		}
		err = e.emit(ctx, tx, actor, eventEnrollmentCreated, ref, domain.ResultSucceeded, map[string]any{
			"token_id": token.ID.String(), "tags": constraints.Tags, "max_nodes": constraints.MaxNodes,
			"source_cidrs": constraints.SourceCIDRs, "expires_at": expiresAt,
		})
		if err != nil {
			return wire.EnrollmentIssued{}, err
		}
		return wire.EnrollmentIssued{ID: token.ID, Token: secret.Reveal(), ExpiresAt: expiresAt}, nil
	})
}

// enrollmentConstraints checks the border of POST /enrollments: a lifetime of
// at most 24 hours (one hour when none is given), at least one node, clean tags
// and parseable CIDRs.
func enrollmentConstraints(now time.Time, r wire.EnrollmentRequest) (database.JoinConstraints, time.Time, error) {
	expiresAt := r.ExpiresAt
	if expiresAt.IsZero() {
		expiresAt = now.Add(defaultEnrollmentTTL)
	}
	if lifetime := expiresAt.Sub(now); lifetime <= 0 || lifetime > database.JoinTokenMaxLifetime {
		return database.JoinConstraints{}, time.Time{}, smerr.New(smerr.CodeInvalidArgument, "", "enrollment expiry must be within 24 hours from now")
	}
	maxNodes := r.MaxNodes
	if maxNodes == 0 {
		maxNodes = 1
	}
	if maxNodes < 1 {
		return database.JoinConstraints{}, time.Time{}, smerr.New(smerr.CodeInvalidArgument, "", "max_nodes must be at least 1")
	}
	tags, err := normalizeTags(r.Tags)
	if err != nil {
		return database.JoinConstraints{}, time.Time{}, err
	}
	cidrs, err := normalizeCIDRs(r.SourceCIDRs)
	if err != nil {
		return database.JoinConstraints{}, time.Time{}, err
	}
	return database.JoinConstraints{Tags: tags, MaxNodes: maxNodes, SourceCIDRs: cidrs}, expiresAt, nil
}

func normalizeCIDRs(in []string) ([]string, error) {
	if len(in) > maxEnrollmentCIDRs {
		return nil, smerr.New(smerr.CodeInvalidArgument, "", fmt.Sprintf("at most %d source CIDRs", maxEnrollmentCIDRs))
	}
	out := make([]string, 0, len(in))
	for _, s := range in {
		prefix, err := netip.ParsePrefix(strings.TrimSpace(s))
		if err != nil {
			return nil, smerr.New(smerr.CodeInvalidArgument, "", "source_cidrs must be CIDR prefixes such as 203.0.113.0/24")
		}
		out = append(out, prefix.Masked().String())
	}
	return dedupe(out), nil
}

// ---- joining --------------------------------------------------------------------

// enrollInput is a validated POST /enroll.
type enrollInput struct {
	tokenHash string
	hostKey   string
	hostname  string
	port      int
	digest    string
}

// Enroll consumes a join token for the node that presents it (exempt:auth: the
// token is the credential). One transaction decides between a retry, which
// returns the node already enrolled, and a new enrollment, which takes a slot.
func (e *EnrollmentService) Enroll(ctx context.Context, source netip.Addr, r wire.EnrollRequest) (wire.Enrolled, error) {
	in, err := e.enrollInput(r)
	if err != nil {
		return wire.Enrolled{}, err
	}
	identity, err := e.identity(ctx)
	if err != nil {
		return wire.Enrolled{}, fmt.Errorf("load instance identity: %w", err)
	}
	return commit(ctx, e.core, Caller{}, func(ctx context.Context, tx *database.Tx) (wire.Enrolled, error) {
		instance, err := database.GetInstance(ctx, tx)
		if err != nil {
			return wire.Enrolled{}, err
		}
		token, err := database.GetJoinTokenByHash(ctx, tx, in.tokenHash)
		if smerr.CodeOf(err) == smerr.CodeNotFound {
			return wire.Enrolled{}, errInvalidJoinToken()
		}
		if err != nil {
			return wire.Enrolled{}, err
		}
		if err := e.requireSource(ctx, tx, token, source); err != nil {
			return wire.Enrolled{}, err
		}
		node, err := e.enrolledNode(ctx, tx, token, in, source, identity)
		if err != nil {
			return wire.Enrolled{}, err
		}
		return enrolledAnswer(instance.ID, node), nil
	})
}

func (e *EnrollmentService) enrollInput(r wire.EnrollRequest) (enrollInput, error) {
	kind, hash, err := e.tokens.Hash(r.Token)
	if err != nil || kind != JoinTokenKind {
		return enrollInput{}, errInvalidJoinToken()
	}
	hostKey := strings.TrimSpace(r.HostPublicKey)
	if _, err := sshnode.ParseHostKey(hostKey); err != nil {
		return enrollInput{}, err
	}
	if err := sshnode.ValidateName(r.Hostname); err != nil {
		return enrollInput{}, err
	}
	port := r.SSHPort
	if port == 0 {
		port = sshnode.DefaultPort
	}
	if port < 1 || port > maxEnrolledPort {
		return enrollInput{}, smerr.New(smerr.CodeInvalidArgument, "", "invalid ssh port")
	}
	return enrollInput{
		tokenHash: hash, hostKey: hostKey, hostname: r.Hostname, port: port,
		digest: database.JoinRequestDigest(hostKey, r.Hostname),
	}, nil
}

func errInvalidJoinToken() error {
	return smerr.New(smerr.CodeUnauthenticated, "", "invalid join token")
}

// requireSource enforces the token's source_cidrs against the client address.
// A refusal is audited and committed.
func (e *EnrollmentService) requireSource(ctx context.Context, tx *database.Tx, token database.JoinToken, source netip.Addr) error {
	if sourceAllowed(token.Constraints.SourceCIDRs, source) {
		return nil
	}
	denied := smerr.New(smerr.CodePolicyDenied, smerr.ReasonDefaultDeny, "enrollment is not allowed from this address")
	if err := e.auditDenied(ctx, tx, token, denied); err != nil {
		return err
	}
	return reject(denied)
}

func sourceAllowed(cidrs []string, source netip.Addr) bool {
	if len(cidrs) == 0 {
		return true
	}
	source = source.Unmap()
	return slices.ContainsFunc(cidrs, func(c string) bool {
		prefix, err := netip.ParsePrefix(c)
		return err == nil && prefix.Contains(source)
	})
}

func (e *EnrollmentService) auditDenied(ctx context.Context, q database.Querier, token database.JoinToken, cause error) error {
	ref := domain.ResourceRef{Type: domain.ResourceInstance, ID: ""}
	if instance, err := database.GetInstance(ctx, q); err == nil {
		ref.ID = instance.ID
	}
	return e.emit(ctx, q, systemActor, eventEnrollmentDenied, ref, domain.ResultDenied,
		map[string]any{"token_id": token.ID.String(), "reason": cause.Error()})
}

// enrolledNode returns the node a lost-response replay maps to, or enrolls a
// new one. A request for a node that is already enrolled never changes it:
// only the exact replay (same token, same digest) is answered (ADR-0022).
func (e *EnrollmentService) enrolledNode(ctx context.Context, tx *database.Tx, token database.JoinToken, in enrollInput, source netip.Addr, identity secrets.Identity) (domain.Node, error) {
	now := e.cfg.Clock.Now()
	replayed, err := database.FindEnrolledNode(ctx, tx, token.ID, in.digest)
	switch {
	case err == nil:
		if err := e.requireLive(ctx, tx, token, now); err != nil {
			return domain.Node{}, err
		}
		return database.GetNode(ctx, tx, replayed)
	case smerr.CodeOf(err) != smerr.CodeNotFound:
		return domain.Node{}, err
	}
	if err := e.refuseEnrolledNode(ctx, tx, token, in); err != nil {
		return domain.Node{}, err
	}
	used, err := database.UseJoinToken(ctx, tx, token.ID, now)
	if smerr.CodeOf(err) == smerr.CodeConflict {
		if auditErr := e.auditDenied(ctx, tx, token, err); auditErr != nil {
			return domain.Node{}, auditErr
		}
		return domain.Node{}, reject(err)
	}
	if err != nil {
		return domain.Node{}, err
	}
	return e.createNode(ctx, tx, used, in, source, identity)
}

// refuseEnrolledNode rejects, audited and without costing a slot, a request
// whose host key and hostname belong to a node that another enrollment created.
func (e *EnrollmentService) refuseEnrolledNode(ctx context.Context, tx *database.Tx, token database.JoinToken, in enrollInput) error {
	_, err := database.FindEnrolledNode(ctx, tx, "", in.digest)
	if smerr.CodeOf(err) == smerr.CodeNotFound {
		return nil
	}
	if err != nil {
		return err
	}
	conflict := smerr.New(smerr.CodeConflict, "", "node is already enrolled")
	if err := e.auditDenied(ctx, tx, token, conflict); err != nil {
		return err
	}
	return reject(conflict)
}

// requireLive refuses a replay on a token that expired or was invalidated.
func (e *EnrollmentService) requireLive(ctx context.Context, tx *database.Tx, token database.JoinToken, now time.Time) error {
	if token.InvalidatedAt == nil && now.Before(token.ExpiresAt) {
		return nil
	}
	expired := smerr.New(smerr.CodeConflict, "", "join token is expired or invalidated")
	if err := e.auditDenied(ctx, tx, token, expired); err != nil {
		return err
	}
	return reject(expired)
}

// createNode records the managed SSH node: the presented host key pinned, the
// dedicated user, the instance key at its current version, and the enrollment
// in metadata for the lost-response replay.
func (e *EnrollmentService) createNode(ctx context.Context, tx *database.Tx, token database.JoinToken, in enrollInput, source netip.Addr, identity secrets.Identity) (domain.Node, error) {
	name, err := e.nodeName(ctx, tx, in)
	if err != nil {
		return domain.Node{}, err
	}
	host := source.Unmap().String()
	if err := sshnode.ValidateEndpoint(host, in.port); err != nil {
		return domain.Node{}, err
	}
	now := e.cfg.Clock.Now()
	credentialRef := pinnedIdentityRef(identity)
	provider, err := database.CreateProvider(ctx, tx, domain.Provider{
		ID: e.cfg.IDs.NewID(), Type: sshnode.ProviderType, Name: name, Origin: domain.ProviderAPI,
		Endpoint: net.JoinHostPort(host, strconv.Itoa(in.port)), CredentialRef: credentialRef,
		CreatedAt: now, UpdatedAt: now,
	})
	if err != nil {
		return domain.Node{}, err
	}
	endpoint := sshnode.Endpoint{Host: host, Port: in.port, User: config.DefaultSSHUser, HostPublicKey: in.hostKey}
	node, err := database.CreateNode(ctx, tx, domain.Node{
		ID: e.cfg.IDs.NewID(), ProviderID: provider.ID, NativeID: name, Name: name, Kind: sshnode.NodeKind,
		ManagementState: domain.ManagementManaged, Reachability: domain.ReachabilityUnknown,
		Endpoint: endpoint.NodeEndpoint(), CredentialRef: credentialRef, Tags: token.Constraints.Tags,
		Metadata: map[string]any{
			database.JoinMetaTokenID: token.ID.String(), database.JoinMetaRequestDigest: in.digest,
			metaJoinAuthorizedKey: identity.AuthorizedKey, metaJoinKeyVersion: identity.Ref.Version,
			metaJoinKeyPrint: identity.FingerprintSHA256,
		},
		CreatedAt: now, UpdatedAt: now,
	})
	if err != nil {
		return domain.Node{}, err
	}
	fingerprint, _ := sshnode.Fingerprint(in.hostKey)
	err = e.emit(ctx, tx, systemActor, eventNodeEnrolled, nodeRef(node.ID), domain.ResultSucceeded, map[string]any{
		"token_id": token.ID.String(), "name": name, "host": host, "port": in.port, "host_key_fingerprint": fingerprint,
	})
	return node, err
}

// nodeName is the hostname, or the hostname with the request digest when that
// name is taken by another node or provider.
func (e *EnrollmentService) nodeName(ctx context.Context, q database.Querier, in enrollInput) (string, error) {
	providers, err := database.ListProviders(ctx, q)
	if err != nil {
		return "", err
	}
	open, err := database.ListOpenTunnelEnrollments(ctx, q)
	if err != nil {
		return "", err
	}
	taken := func(name string) bool {
		return slices.ContainsFunc(providers, func(p domain.Provider) bool { return p.Name == name }) ||
			slices.ContainsFunc(open, func(t database.TunnelEnrollment) bool { return t.Name == name })
	}
	if !taken(in.hostname) {
		return in.hostname, nil
	}
	const suffixLen = 8
	base := in.hostname[:min(len(in.hostname), 54)]
	if name := base + "-" + in.digest[:suffixLen]; !taken(name) {
		return name, nil
	}
	return "", smerr.New(smerr.CodeConflict, "", fmt.Sprintf("a node or provider named %q already exists", in.hostname))
}

func enrolledAnswer(instance domain.ID, node domain.Node) wire.Enrolled {
	version, _ := node.Metadata[metaJoinKeyVersion].(float64)
	key, _ := node.Metadata[metaJoinAuthorizedKey].(string)
	fingerprint, _ := node.Metadata[metaJoinKeyPrint].(string)
	return wire.Enrolled{
		NodeID: node.ID, InstanceID: instance, SSHUser: node.Endpoint.User,
		AuthorizedKey: key, KeyVersion: int(version), FingerprintSHA256: fingerprint,
	}
}
