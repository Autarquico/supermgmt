package cli

import (
	"fmt"
	"io"
	"time"

	"github.com/spf13/cobra"

	"github.com/autarquico/supermgmt/internal/api/wire"
	"github.com/autarquico/supermgmt/internal/client"
	smerr "github.com/autarquico/supermgmt/internal/errors"
)

// nodesWithEnrollments is `sm nodes list --json` when nodes are being enrolled; without open enrollments
// the output is the plain page.
type nodesWithEnrollments struct {
	wire.Page[wire.Node]
	TunnelEnrollments []wire.TunnelEnrollment `json:"tunnel_enrollments"`
}

// openEnrollments reads the enrollments that are not nodes yet. A daemon that does not know them
// (an older one, or without the service) shows no section; any other failure is a warning, since the
// nodes themselves were read.
func openEnrollments(cmd *cobra.Command, api *client.Client) []wire.TunnelEnrollment {
	page, err := api.ListTunnelEnrollments(cmd.Context())
	if err == nil {
		return page.Items
	}
	if code := smerr.CodeOf(err); code != smerr.CodeNotFound && code != smerr.CodeCapabilityUnavailable {
		_, _ = fmt.Fprintf(cmd.ErrOrStderr(), "warning: cannot read the open enrollments: %v\n", err)
	}
	return nil
}

func writeEnrollments(w io.Writer, enrollments []wire.TunnelEnrollment) error {
	if _, err := fmt.Fprintln(w, "\nOpen enrollments (tunnel nodes waiting to be added):"); err != nil {
		return err
	}
	rows := make([][]string, len(enrollments))
	for i, e := range enrollments {
		rows[i] = []string{e.Name, orDash(e.Environment), describePhase(e), e.ExpiresAt.Local().Format(time.DateTime), e.Hostname}
	}
	return table(w, []string{"NAME", "ENVIRONMENT", "STATE", "EXPIRES", "HOSTNAME"}, rows)
}
