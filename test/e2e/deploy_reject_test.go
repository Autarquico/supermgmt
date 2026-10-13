//go:build e2e && fixtures

package e2e_test

import (
	"fmt"
	"strings"
	"testing"

	"github.com/autarquico/supermgmt/internal/api/wire"
	"github.com/autarquico/supermgmt/internal/deployments"
	smerr "github.com/autarquico/supermgmt/internal/errors"
)

const rejectManifestHead = `apiVersion: supermgmt.dev/v1
kind: Application
metadata:
  name: shop
spec:
  deployment:
    strategy: docker-compose
    composeFile: compose.yaml
    service: web
`

const rejectPrivilegedCompose = `services:
  web:
    image: ` + m4RegistryHost + `/` + m4ImageRepo + `:placeholder
    privileged: true
    ports:
      - {target: 8080, published: 8080, host_ip: 127.0.0.1}
`

// rejectDeployment deploys commit once its CI is green and returns the deployment once the control
// plane has refused it (or, wrongly, finished it).
func (w *m4World) rejectDeployment(target wire.AppTarget, commit string, run int64) wire.Deployment {
	w.t.Helper()
	digest := w.sim.pushImage(m4Image{Version: commit[:7]})
	w.sim.attest(digest, commit)
	d := w.deployShop(target, commit, digest)
	w.deployTellCIPassed(commit, run)
	return w.waitDeployment(d.ID, m4DeployTimeout, string(deployments.StateFailed), string(deployments.StateSucceeded))
}

func (w *m4World) requireRejected(d wire.Deployment, want smerr.Reason) {
	w.t.Helper()
	if d.State != string(deployments.StateFailed) || d.StateReason != want {
		w.t.Fatalf("deployment ended %s (%s/%s), want failed %s\nsteps:\n%s", d.State, d.StateCode, d.StateReason, want, m4Timeline(d))
	}
}

// requireNothingRan fails when the node holds a container of the target's Compose project.
func (w *m4World) requireNothingRan(target wire.AppTarget) {
	w.t.Helper()
	out := w.node.c.MustExec(w.ctx(), "docker", "ps", "--all", "--filter", "label=com.docker.compose.project="+target.ComposeProject, "--format", "{{.Names}}")
	if strings.TrimSpace(out) != "" {
		w.t.Fatalf("a rejected deployment left containers on the node: %q", out)
	}
}

// TestM4_RepositoryComposePrivilegedRejected
//
// Spec scenario "Compose privilegiado rechazado" (PLAN §9 row 4): the Compose file the repository
// holds at the CI-passed commit asks for `privileged: true`, so the deployment is refused with
// COMPOSE_REJECTED and nothing reaches the node.
func TestM4_RepositoryComposePrivilegedRejected(t *testing.T) {
	w := newM4ServerWorld(t)
	provider, node := w.waitForStaticConfig()
	w.sim.addShopRepository()
	w.prepareNode(node)
	req := deployAppRequest(provider, m4AppName)
	req.ComposeSource, req.ComposeContent = "repository", ""
	target := w.deployCreateApp(req, node, shopPolicy())

	const commit = "5555555555555555555555555555555555555555"
	w.sim.deployAddFile(commit, ".supermgmt.yaml", rejectManifestHead)
	w.sim.deployAddFile(commit, "compose.yaml", rejectPrivilegedCompose)
	d := w.rejectDeployment(target, commit, 1)

	t.Run("the deployment is refused as COMPOSE_REJECTED", func(t *testing.T) { w.requireRejected(d, smerr.ReasonComposeRejected) })
	t.Run("nothing reaches the node", func(t *testing.T) { w.requireNothingRan(target) })
}

// TestM4_ManifestHealthOffNodeRejected
//
// Spec scenario "health URL fuera del nodo rechazada" (PLAN §9 row 6): a manifest whose health check
// names a URL or a host instead of a port and a path on the node is refused as MANIFEST_INVALID.
func TestM4_ManifestHealthOffNodeRejected(t *testing.T) {
	w := newM4ServerWorld(t)
	provider, node := w.waitForStaticConfig()
	w.sim.addShopRepository()
	w.prepareNode(node)
	target := w.createShop(provider, node)

	offNode := []struct{ name, commit, health string }{
		{"a health url", "6666666666666666666666666666666666666666", "url: http://203.0.113.9/health"},
		{"a health host", "7777777777777777777777777777777777777777", "host: 203.0.113.9"},
	}
	for i, tc := range offNode {
		t.Run(tc.name, func(t *testing.T) {
			manifest := fmt.Sprintf("%s  health:\n    type: http\n    port: %d\n    path: /health\n    %s\n", rejectManifestHead, m4AppPort, tc.health)
			w.sim.deployAddFile(tc.commit, ".supermgmt.yaml", manifest)
			d := w.rejectDeployment(target, tc.commit, int64(i+1))
			w.requireRejected(d, smerr.ReasonManifestInvalid)
			w.requireNothingRan(target)
		})
	}
}
