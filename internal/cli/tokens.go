package cli

import (
	"fmt"
	"io"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/autarquico/supermgmt/internal/api/wire"
	"github.com/autarquico/supermgmt/internal/domain"
)

const (
	hoursPerDay     = 24
	maxTokenDays    = 365
	defaultTokenTTL = "90d"
)

func newTokensCmd(env []string) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "tokens",
		Short: "List, create and revoke API tokens",
		Args:  noArgs,
		RunE:  func(cmd *cobra.Command, _ []string) error { return cmd.Help() },
	}
	cmd.AddCommand(newTokensListCmd(env), newTokensCreateCmd(env), newTokensRevokeCmd(env))
	return cmd
}

func newTokensListCmd(env []string) *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "List your API tokens (their values are never shown again)",
		Args:  noArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			api, err := newClient(cmd, env)
			if err != nil {
				return err
			}
			page, err := api.ListTokens(cmd.Context())
			if err != nil {
				return err
			}
			return emit(cmd, page, func(w io.Writer) error { return writeTokens(w, page.Items) })
		},
	}
}

func writeTokens(w io.Writer, tokens []wire.Token) error {
	rows := make([][]string, len(tokens))
	for i, t := range tokens {
		state := "active"
		if t.RevokedAt != nil {
			state = "revoked"
		}
		rows[i] = []string{
			string(t.ID), t.Name, state, orDash(strings.Join(t.Scopes, ",")),
			formatTime(t.ExpiresAt), formatTimePtr(t.LastUsedAt),
		}
	}
	return table(w, []string{"ID", "NAME", "STATE", "SCOPES", "EXPIRES", "LAST USED"}, rows)
}

func newTokensCreateCmd(env []string) *cobra.Command {
	var name, expiresIn, expiresAt string
	var scopes []string
	cmd := &cobra.Command{
		Use:   "create",
		Short: "Create an API token (the value is shown once)",
		Long: "Create an API token for automation. It can only narrow what you may do: --scope lists action patterns,\n" +
			"empty means all of yours. Expiry is mandatory and at most 365 days. The value is printed once, on stdout.",
		Args: noArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if name == "" {
				return usageErrorf("--name is required")
			}
			expiry, err := tokenExpiry(expiresIn, expiresAt)
			if err != nil {
				return err
			}
			api, err := newClient(cmd, env)
			if err != nil {
				return err
			}
			issued, err := api.CreateToken(cmd.Context(), wire.CreateTokenRequest{Name: name, Scopes: nonNilStrings(scopes), ExpiresAt: expiry})
			if err != nil {
				return err
			}
			return emit(cmd, issued, func(w io.Writer) error {
				_, _ = fmt.Fprintf(cmd.ErrOrStderr(), "token %s (%s) expires %s; this is the only time its value is shown\n",
					issued.Token.ID, issued.Token.Name, formatTime(issued.Token.ExpiresAt))
				_, err := fmt.Fprintln(w, issued.Value)
				return err
			})
		},
	}
	cmd.Flags().StringVar(&name, "name", "", "a name for the token (unique among yours)")
	cmd.Flags().StringVar(&expiresIn, "expires-in", defaultTokenTTL, "lifetime, e.g. 30d or 720h (at most 365d)")
	cmd.Flags().StringVar(&expiresAt, "expires-at", "", "expiry as an RFC 3339 time, instead of --expires-in")
	cmd.Flags().StringSliceVar(&scopes, "scope", nil, "action pattern the token is limited to (repeatable)")
	return cmd
}

func nonNilStrings(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

// tokenExpiry resolves the flags to the absolute expiry the API wants.
func tokenExpiry(expiresIn, expiresAt string) (time.Time, error) {
	now := domain.SystemClock{}.Now()
	if expiresAt != "" {
		t, err := time.Parse(time.RFC3339, expiresAt)
		if err != nil {
			return time.Time{}, usageErrorf("--expires-at %q is not an RFC 3339 time", expiresAt)
		}
		return checkExpiry(now, t)
	}
	ttl, err := parseLifetime(expiresIn)
	if err != nil {
		return time.Time{}, err
	}
	return checkExpiry(now, now.Add(ttl))
}

func checkExpiry(now, expiry time.Time) (time.Time, error) {
	switch {
	case !expiry.After(now):
		return time.Time{}, usageErrorf("the expiry must be in the future")
	case expiry.After(now.Add(maxTokenDays * hoursPerDay * time.Hour)):
		return time.Time{}, usageErrorf("a token lives at most %d days", maxTokenDays)
	}
	return expiry.UTC(), nil
}

// parseLifetime accepts Go durations and whole days ("90d").
func parseLifetime(s string) (time.Duration, error) {
	if days, ok := strings.CutSuffix(s, "d"); ok {
		n, err := strconv.Atoi(days)
		if err != nil || n <= 0 {
			return 0, usageErrorf("--expires-in %q: want a positive number of days like 90d", s)
		}
		return time.Duration(n) * hoursPerDay * time.Hour, nil
	}
	d, err := time.ParseDuration(s)
	if err != nil || d <= 0 {
		return 0, usageErrorf("--expires-in %q: want a duration like 720h or 90d", s)
	}
	return d, nil
}

func newTokensRevokeCmd(env []string) *cobra.Command {
	return &cobra.Command{
		Use:   "revoke <token-id>",
		Short: "Revoke an API token (it stops working on its next request)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			id, err := parseID(args[0])
			if err != nil {
				return err
			}
			api, err := newClient(cmd, env)
			if err != nil {
				return err
			}
			if err := api.RevokeToken(cmd.Context(), id); err != nil {
				return err
			}
			return emit(cmd, map[string]string{"revoked": string(id)}, func(w io.Writer) error {
				_, err := fmt.Fprintf(w, "revoked token %s\n", id)
				return err
			})
		},
	}
}
