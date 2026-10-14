package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	"github.com/autarquico/supermgmt/internal/api"
	"github.com/autarquico/supermgmt/internal/api/wire"
	"github.com/autarquico/supermgmt/internal/client"
	"github.com/autarquico/supermgmt/internal/domain"
	smerr "github.com/autarquico/supermgmt/internal/errors"
)

const (
	adminHost           = "admin"
	adminRequestTimeout = 30 * time.Second
	maxAdminResponse    = 1 << 20
)

// newAdminCmd is `sm admin`: the server's admin socket (spec §23.1), reachable
// by root and the service user. It is not an API client: nothing here needs a
// login, which is the point when no admin exists yet.
func newAdminCmd(env []string) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "admin",
		Short: "Administer a server through its admin socket (root or the service user)",
		Args:  noArgs,
	}
	cmd.AddCommand(newBootstrapCodeCmd(env), newGrantCmd(env), newRestoreCompleteCmd(env))
	return cmd
}

func newBootstrapCodeCmd(env []string) *cobra.Command {
	return &cobra.Command{
		Use:   "bootstrap-code",
		Short: "Issue a one-time code for the first administrator and print it",
		Long: "Issues a new one-time bootstrap code and prints only the code on stdout. " +
			"Any unconsumed code is invalidated. It works while the server has no administrator, and during a restore hold.",
		Args: noArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			admin, err := adminFor(cmd, env)
			if err != nil {
				return err
			}
			issued, err := adminCall[wire.BootstrapCodeIssued](cmd.Context(), admin, http.MethodPost, wire.AdminPathBootstrapCode, nil)
			if err != nil {
				return err
			}
			if asJSON, _ := cmd.Flags().GetBool("json"); asJSON {
				return writeJSON(cmd.OutOrStdout(), issued)
			}
			_, _ = fmt.Fprintln(cmd.ErrOrStderr(), "bootstrap code valid until", issued.ExpiresAt.Local().Format(time.RFC3339))
			_, err = fmt.Fprintln(cmd.OutOrStdout(), issued.Code)
			return err
		},
	}
}

func newGrantCmd(env []string) *cobra.Command {
	return &cobra.Command{
		Use:   "grant <identity-id> <role>",
		Short: "Bind a role to an identity (recovery when no administrator can log in)",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			id, err := domain.ParseID(args[0])
			if err != nil {
				return usageErrorf("%q is not an identity id", args[0])
			}
			admin, err := adminFor(cmd, env)
			if err != nil {
				return err
			}
			if _, err := adminCall[struct{}](cmd.Context(), admin, http.MethodPost, wire.AdminPathGrant, wire.GrantRequest{IdentityID: id, Role: args[1]}); err != nil {
				return err
			}
			_, err = fmt.Fprintf(cmd.OutOrStdout(), "granted %s to %s\n", args[1], id)
			return err
		},
	}
}

func newRestoreCompleteCmd(env []string) *cobra.Command {
	return &cobra.Command{
		Use:   "restore-complete",
		Short: "End the restore hold after reviewing sm doctor and the interrupted jobs",
		Args:  noArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			admin, err := adminFor(cmd, env)
			if err != nil {
				return err
			}
			if _, err := adminCall[wire.RestoreCompleted](cmd.Context(), admin, http.MethodPost, wire.AdminPathRestoreComplete, nil); err != nil {
				return err
			}
			_, err = fmt.Fprintln(cmd.OutOrStdout(), "restore hold ended")
			return err
		},
	}
}

// adminFor finds the admin socket of the server the configuration describes.
func adminFor(cmd *cobra.Command, env []string) (*http.Client, error) {
	configFlag, _ := cmd.Flags().GetString("config")
	file := configPath(configFlag, env)
	cfg, err := loadServerConfig(file, env)
	if err != nil {
		return nil, err
	}
	return adminClient(cfg.Server.AdminSocket), nil
}

// adminClient dials the admin socket and, before it sends a byte, proves that
// the process that accepted is the owner of the socket file: a root caller
// must not hand its requests to whoever bound the path.
func adminClient(socket string) *http.Client {
	return &http.Client{
		Timeout: adminRequestTimeout,
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) { return dialAdmin(ctx, socket) },
		},
	}
}

func dialAdmin(ctx context.Context, socket string) (net.Conn, error) {
	var dialer net.Dialer
	conn, err := dialer.DialContext(ctx, "unix", socket)
	if err != nil {
		return nil, &client.DaemonUnavailableError{
			Detail: fmt.Sprintf("cannot reach the admin socket %s: is the server running, and are you root or the service user?", socket), Err: err,
		}
	}
	if err := verifySocketOwner(conn, socket); err != nil {
		_ = conn.Close()
		return nil, err
	}
	return conn, nil
}

func verifySocketOwner(conn net.Conn, socket string) error {
	info, err := os.Lstat(socket)
	if err != nil {
		return fmt.Errorf("inspect the admin socket: %w", err)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	unixConn, isUnix := conn.(*net.UnixConn)
	if !ok || !isUnix {
		return errors.New("cannot verify who owns the admin socket on this platform")
	}
	peer, err := api.PeerUID(unixConn)
	if err != nil {
		return fmt.Errorf("verify the admin socket peer: %w", err)
	}
	if peer != stat.Uid {
		return smerr.New(smerr.CodeUnauthenticated, "", fmt.Sprintf("refusing the admin socket %s: it is served by uid %d, not by the owner of the socket file (uid %d)", socket, peer, stat.Uid))
	}
	return nil
}

// adminCall sends one request to the admin socket and decodes its envelope.
func adminCall[T any](ctx context.Context, admin *http.Client, method, path string, body any) (T, error) {
	var zero T
	var payload io.Reader = http.NoBody
	if body != nil {
		encoded, err := json.Marshal(body)
		if err != nil {
			return zero, fmt.Errorf("encode the request: %w", err)
		}
		payload = bytes.NewReader(encoded)
	}
	req, err := http.NewRequestWithContext(ctx, method, "http://"+adminHost+path, payload)
	if err != nil {
		return zero, err
	}
	resp, err := admin.Do(req)
	if err != nil {
		return zero, unwrapDaemonError(err)
	}
	defer func() { _ = resp.Body.Close() }()
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxAdminResponse))
	if err != nil {
		return zero, fmt.Errorf("read the admin socket's answer: %w", err)
	}
	if resp.StatusCode >= http.StatusBadRequest {
		var failed wire.ErrorEnvelope
		if err := json.Unmarshal(data, &failed); err != nil || failed.Error.Code == "" {
			return zero, fmt.Errorf("the admin socket answered %s", resp.Status)
		}
		return zero, failed.Error.Err()
	}
	var ok wire.Envelope[T]
	if err := json.Unmarshal(data, &ok); err != nil {
		return zero, smerr.Wrap(err, smerr.CodeInternal, "", "the admin socket sent an unreadable response")
	}
	return ok.Data, nil
}

// unwrapDaemonError lifts the typed dial errors out of *url.Error so the exit
// code and message are those of the failure.
func unwrapDaemonError(err error) error {
	var unavailable *client.DaemonUnavailableError
	if errors.As(err, &unavailable) {
		return unavailable
	}
	var typed *smerr.Error
	if errors.As(err, &typed) {
		return typed
	}
	return err
}
