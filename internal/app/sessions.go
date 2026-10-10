package app

import (
	"context"
	"slices"
	"time"

	"github.com/autarquico/supermgmt/internal/api/wire"
	"github.com/autarquico/supermgmt/internal/database"
	"github.com/autarquico/supermgmt/internal/domain"
	smerr "github.com/autarquico/supermgmt/internal/errors"
	"github.com/autarquico/supermgmt/internal/policy"
)

// sessionTTL is how long an issued interactive session may stay open before
// the sweeper marks it abandoned (plan Q7).
const sessionTTL = 24 * time.Hour

// Sessions audits interactive SSH handoffs (spec §8.4, §12): the session start
// and end, never the keystrokes. The terminal itself is OpenSSH, run by the
// client with the user's own credentials.
type Sessions struct {
	core
}

// NewSessions validates cfg.
func NewSessions(cfg Config) (*Sessions, error) {
	c, err := newCore(cfg)
	if err != nil {
		return nil, err
	}
	return &Sessions{core: c}, nil
}

// EndSession is how a handoff ended: exited (with the exit code) or
// launch_failed (no process ran).
type EndSession struct {
	Reason   wire.EndReason
	ExitCode *int
}

// Open issues a session on a node and returns what the client needs to start
// OpenSSH. It needs node.connect on the node, and the tool must be available
// there. A retry with the same Idempotency-Key is replayed, not issued again;
// the Responder of such a request receives a wire.SessionOpened.
func (s *Sessions) Open(ctx context.Context, by Caller, node domain.ID, tool string) (Session, ConnectInfo, error) {
	opened, err := commit(ctx, s.core, by, func(ctx context.Context, tx *database.Tx) (wire.SessionOpened, error) {
		if !slices.Contains(wire.AllTools(), wire.Tool(tool)) {
			return wire.SessionOpened{}, smerr.New(smerr.CodeInvalidArgument, "", "unknown tool")
		}
		actor, target, err := s.authorizeConnect(ctx, tx, by, node)
		if err != nil {
			return wire.SessionOpened{}, err
		}
		if err := s.requireTool(ctx, tx, node, wire.Tool(tool)); err != nil {
			return wire.SessionOpened{}, err
		}
		stored, err := database.CreateInteractiveSession(ctx, tx, database.InteractiveSession{
			ID: s.cfg.IDs.NewID(), IdentityID: by.ID, NodeID: node, Tool: database.SessionTool(tool), CreatedAt: s.cfg.Clock.Now(),
		})
		if err != nil {
			return wire.SessionOpened{}, err
		}
		err = s.emit(ctx, tx, actor, "node.session.opened", nodeRef(node), domain.ResultSucceeded,
			map[string]any{"session_id": stored.ID.String(), "tool": tool})
		return wire.SessionOpened{Session: sessionView(stored), ConnectInfo: connectInfoOf(target)}, err
	})
	return opened.Session, opened.ConnectInfo, err
}

// authorizeConnect checks node.connect on the node (which needs capability
// node.ssh) and returns it. A refusal is audited and rejects.
func (s *Sessions) authorizeConnect(ctx context.Context, q database.Querier, by Caller, id domain.ID) (domain.Actor, domain.Node, error) {
	actor, err := s.beginRequest(ctx, q, by)
	if err != nil {
		return domain.Actor{}, domain.Node{}, err
	}
	target, err := resolve(ctx, q, domain.ResourceRef{Type: domain.ResourceNode, ID: id})
	if err != nil {
		return domain.Actor{}, domain.Node{}, err
	}
	res := s.authorize(policy.Request{Actor: actor, Action: "node.connect", Targets: []policy.Target{target.target}})
	if err := s.auditDecision(ctx, q, actor, "node.connect", target.target.Ref, res); err != nil {
		return domain.Actor{}, domain.Node{}, err
	}
	if err := decisionError(res); err != nil {
		return domain.Actor{}, domain.Node{}, reject(err)
	}
	node, err := database.GetNode(ctx, q, id)
	return actor, node, err
}

// requireTool refuses a tool the node does not have. lazydocker, btop and tmux
// are never installed for the user (spec §17.1), so a missing one is
// CAPABILITY_UNAVAILABLE and the client shows the instructions instead.
func (s *Sessions) requireTool(ctx context.Context, q database.Querier, node domain.ID, tool wire.Tool) error {
	if tool == wire.ToolShell {
		return nil
	}
	capability, err := database.GetNodeCapability(ctx, q, node, "tool."+string(tool))
	if smerr.CodeOf(err) == smerr.CodeNotFound || (err == nil && !capability.Available) {
		return smerr.New(smerr.CodeCapabilityUnavailable, "", string(tool)+" is not installed on the node")
	}
	return err
}

// End records how a session ended. It is bound to the caller and the node;
// the first end wins and later calls return the stored outcome unchanged.
func (s *Sessions) End(ctx context.Context, by Caller, node, id domain.ID, r EndSession) (Session, error) {
	return commit(ctx, s.core, by, func(ctx context.Context, tx *database.Tx) (Session, error) {
		actor, err := s.beginRequest(ctx, tx, by)
		if err != nil {
			return wire.Session{}, err
		}
		stored, first, err := database.EndInteractiveSession(ctx, tx, id, by.ID, node, database.SessionEnd{
			Reason: database.SessionEnding(r.Reason), ExitCode: r.ExitCode, At: s.cfg.Clock.Now(),
		})
		if err != nil {
			return wire.Session{}, err
		}
		if first {
			data := map[string]any{"session_id": id.String(), "reason": string(r.Reason)}
			if r.ExitCode != nil {
				data["exit_code"] = *r.ExitCode
			}
			err = s.emit(ctx, tx, actor, "node.session.ended", nodeRef(node), domain.ResultSucceeded, data)
		}
		return sessionView(stored), err
	})
}

func sessionView(s database.InteractiveSession) wire.Session {
	out := wire.Session{
		ID: s.ID, NodeID: s.NodeID, Tool: wire.Tool(s.Tool), State: wire.SessionState(s.State),
		ExitCode: s.ExitCode, CreatedAt: s.CreatedAt, EndedAt: s.EndedAt,
	}
	if s.EndReason != "" {
		reason := wire.EndReason(s.EndReason)
		out.EndReason = &reason
	}
	return out
}
