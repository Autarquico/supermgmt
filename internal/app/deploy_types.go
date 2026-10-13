package app

import (
	"context"

	"github.com/autarquico/supermgmt/internal/api/wire"
	"github.com/autarquico/supermgmt/internal/domain"
)

// The views are the wire shapes themselves, under the names of the contract.
type (
	AppView        = wire.App
	AppTargetView  = wire.AppTarget
	RepositoryView = wire.Repository
	DeploymentView = wire.Deployment
)

// CreateDeployment is a provisional deployment request (ADR-0011): only the
// target, the exact commit and the requested digests; everything else is
// resolved at finalization.
type CreateDeployment struct {
	AppTargetID domain.ID
	CommitSHA   string
	Images      []RequestedImage
}

// RequestedImage is a service's digest as the requester named it.
type RequestedImage struct {
	Service string
	Digest  string
}

// CIWatcher moves waiting_ci deployments forward. Run polls (local mode, and
// the server-mode backstop at github.ci_poll_max); Nudge re-evaluates the
// deployments waiting on one commit once, after a verified webhook.
type CIWatcher interface {
	Run(ctx context.Context) error
	Nudge(repositoryID int64, sha string)
}
