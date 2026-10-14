package cli

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"

	"github.com/autarquico/supermgmt/internal/api/wire"
	"github.com/autarquico/supermgmt/internal/audit"
	"github.com/autarquico/supermgmt/internal/client"
	"github.com/autarquico/supermgmt/internal/config"
	"github.com/autarquico/supermgmt/internal/domain"
	smerr "github.com/autarquico/supermgmt/internal/errors"
)

// envNoAutostart set to a non-empty value other than "0" stops every API
// command from spawning a daemon: scripts and CI that must never start one.
const envNoAutostart = "SUPERMGMT_NO_AUTOSTART"

// clientCommands are the commands that talk to the daemon (spec §4). The root
// command registers them with root.AddCommand(clientCommands(env)...).
func clientCommands(env []string) []*cobra.Command {
	return []*cobra.Command{
		newNodesCmd(env), newServicesCmd(env), newJobsCmd(env), newApprovalsCmd(env),
		newSSHCmd(env), newDockerCmd(env), newStatusCmd(env), newEventsCmd(env), newSSHKeyCmd(env),
		newLoginCmd(env, defaultLoginDeps(env)), newLogoutCmd(env), newProfileCmd(env), newTokensCmd(env),
		newSecretsCmd(env), newBackupCmd(env), newEnrollmentsCmd(env), newAppsCmd(env), newMCPCmd(env),
	}
}

// newClient builds the API client for cmd: the remote server of the current
// profile, or the local daemon (spec §8.4, ADR-0014).
func newClient(cmd *cobra.Command, env []string) (*client.Client, error) {
	api, _, err := connect(cmd, env)
	return api, err
}

// connect is newClient that also says which target it chose.
func connect(cmd *cobra.Command, env []string) (*client.Client, target, error) {
	where, err := resolveTarget(cmd, env)
	if err != nil {
		return nil, target{}, err
	}
	if where.remote != nil {
		api, err := remoteClient(cmd.Context(), env, where.name, *where.remote)
		return api, where, err
	}
	api, err := newLocalClient(env, where.configFile)
	return api, where, err
}

// newLocalClient dials the daemon the configuration file describes.
func newLocalClient(env []string, configFlag string) (*client.Client, error) {
	return newLocalClientWith(env, configFlag, "")
}

// newLocalClientWith is newLocalClient that sends token as the bearer
// credential (an MCP client's token, ADR-0032); "" sends none.
func newLocalClientWith(env []string, configFlag string, token audit.Secret) (*client.Client, error) {
	socket, stateDir, err := daemonLocation(configFlag, env)
	if err != nil {
		return nil, err
	}
	opts := client.Options{Socket: socket, Token: token}
	if v := envMap(env)[envNoAutostart]; v == "" || v == "0" {
		exe, err := os.Executable()
		if err != nil {
			return nil, fmt.Errorf("locate the sm executable to start the daemon: %w", err)
		}
		args := []string{"daemon"}
		if configFlag != "" {
			args = append(args, "--config", configFlag)
		}
		opts.Autostart = &client.Autostart{Executable: exe, Args: args, LogPath: filepath.Join(stateDir, "daemon.log")}
	}
	return client.New(opts), nil
}

// daemonLocation is the socket to dial and the state dir that holds daemon.log.
func daemonLocation(configFlag string, env []string) (socket, stateDir string, err error) {
	path := configPath(configFlag, env)
	if !fileExists(path) {
		paths := localPaths(env)
		return paths.Socket, paths.StateDir, nil
	}
	result, err := config.Load(path, env)
	if err != nil {
		return "", "", err
	}
	cfg := result.Config
	if cfg.Instance.Mode == config.ModeServer {
		return socketPath(cfg, env), config.ServerPaths().StateDir, nil
	}
	return socketPath(cfg, env), localPaths(env).StateDir, nil
}

func wantsJSON(cmd *cobra.Command) bool {
	asJSON, _ := cmd.Flags().GetBool("json")
	return asJSON
}

// emit writes v as JSON with --json, otherwise whatever human renders.
func emit(cmd *cobra.Command, v any, human func(w io.Writer) error) error {
	if wantsJSON(cmd) {
		return writeJSON(cmd.OutOrStdout(), v)
	}
	return human(cmd.OutOrStdout())
}

// table renders rows under header with aligned columns.
func table(w io.Writer, header []string, rows [][]string) error {
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	_, _ = fmt.Fprintln(tw, strings.Join(header, "\t"))
	for _, row := range rows {
		_, _ = fmt.Fprintln(tw, strings.Join(row, "\t"))
	}
	return tw.Flush()
}

// fields renders "key: value" lines with aligned values.
func fields(w io.Writer, pairs [][2]string) error {
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	for _, p := range pairs {
		_, _ = fmt.Fprintf(tw, "%s:\t%s\n", p[0], p[1])
	}
	return tw.Flush()
}

func moreHint(w io.Writer, nextCursor string) {
	if nextCursor != "" {
		_, _ = fmt.Fprintf(w, "more results: --cursor %s\n", nextCursor)
	}
}

func addPageFlags(cmd *cobra.Command) *wire.PageQuery {
	q := &wire.PageQuery{}
	cmd.Flags().IntVar(&q.Limit, "limit", 0, "maximum items per page (default 50, max 500)")
	cmd.Flags().StringVar(&q.Cursor, "cursor", "", "continue after this cursor")
	return q
}

func parseID(arg string) (domain.ID, error) {
	id, err := domain.ParseID(arg)
	if err != nil {
		return "", usageErrorf("%q is not an id", arg)
	}
	return id, nil
}

// confirm asks the user to type "yes" unless assumeYes. Anything else, or no
// input at all, declines: nothing proceeds on an implied answer.
func confirm(cmd *cobra.Command, question string, assumeYes bool) error {
	if assumeYes {
		return nil
	}
	_, _ = fmt.Fprintf(cmd.ErrOrStderr(), "%s Type 'yes' to continue: ", question)
	line, _ := bufio.NewReader(cmd.InOrStdin()).ReadString('\n')
	if strings.TrimSpace(line) != "yes" {
		return usageErrorf("not confirmed")
	}
	return nil
}

// describeSubmission is the one-line outcome of a submitted job.
func describeSubmission(s wire.Submission) string {
	line := fmt.Sprintf("job %s (%s) is %s", s.Job.ID, s.Job.Type, s.Job.State)
	if s.Policy.ApprovalRequired {
		line += fmt.Sprintf("; approval required (quorum %d)", s.Policy.Quorum)
	}
	return line
}

func submissionOutput(cmd *cobra.Command, s wire.Submission) error {
	return emit(cmd, s, func(w io.Writer) error {
		_, err := fmt.Fprintln(w, describeSubmission(s))
		return err
	})
}

// directOutput prints the result of a `direct` action: applied at once, or
// pending as a control_plane.apply job.
func directOutput[T any](cmd *cobra.Command, d wire.Direct[T], applied func(T) string) error {
	return emit(cmd, d, func(w io.Writer) error {
		if d.Applied != nil {
			_, err := fmt.Fprintln(w, applied(*d.Applied))
			return err
		}
		if d.Pending != nil {
			_, err := fmt.Fprintln(w, describeSubmission(*d.Pending))
			return err
		}
		return smerr.New(smerr.CodeInternal, "", "daemon answered neither applied nor pending")
	})
}

func formatTime(t time.Time) string { return t.UTC().Format(time.RFC3339) }

func formatTimePtr(t *time.Time) string {
	if t == nil {
		return "-"
	}
	return formatTime(*t)
}

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}
