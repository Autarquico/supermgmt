package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"runtime"

	"github.com/spf13/cobra"

	"github.com/autarquico/supermgmt/internal/client"
)

// profilesFile is where `sm profile` keeps the profiles: next to the user's
// configuration, with the installer's empty one (spec Appendix B).
func profilesFile(env []string) string {
	return filepath.Join(filepath.Dir(localPaths(env).Config), client.ProfilesFileName)
}

func credentialStore(env []string) client.CredentialStore {
	return client.OpenCredentialStore(runtime.GOOS, env, filepath.Dir(localPaths(env).Config))
}

// target is what a command talks to: a remote server through a profile, or
// the local daemon described by a configuration file.
type target struct {
	// name is the profile, "" when none applies.
	name string
	// remote is nil for the local daemon.
	remote *client.Profile
	// configFile is the local daemon's configuration ("" = the default one).
	configFile string
}

// resolveTarget decides where a command goes. An explicit --config always
// means the local instance it names. Otherwise the current profile decides,
// and with none the local default applies, exactly as in M1.
func resolveTarget(cmd *cobra.Command, env []string) (target, error) {
	if configFlag, _ := cmd.Flags().GetString("config"); configFlag != "" {
		return target{configFile: configFlag}, nil
	}
	profiles, err := client.LoadProfiles(profilesFile(env))
	if err != nil {
		return target{}, err
	}
	name, profile, ok := profiles.Active()
	switch {
	case !ok:
		return target{}, nil
	case profile.Type == client.ProfileLocal:
		return target{name: name, configFile: profile.Config}, nil
	}
	return target{name: name, remote: &profile}, nil
}

// remoteClient builds the client of a remote profile with its stored token.
func remoteClient(ctx context.Context, env []string, name string, profile client.Profile) (*client.Client, error) {
	token, err := credentialStore(env).Get(ctx, name)
	if err != nil && !errors.Is(err, client.ErrNoCredential) {
		return nil, fmt.Errorf("read the stored credential of profile %s: %w", name, err)
	}
	return client.NewRemote(client.Remote{URL: profile.URL, CAFile: profile.CAFile, Token: token}, client.Options{})
}

// ---- sm profile ----------------------------------------------------------------

func newProfileCmd(env []string) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "profile",
		Short: "Manage the servers sm talks to",
		Args:  noArgs,
		RunE:  func(cmd *cobra.Command, _ []string) error { return cmd.Help() },
	}
	cmd.AddCommand(newProfileAddCmd(env), newProfileListCmd(env), newProfileUseCmd(env), newProfileRemoveCmd(env))
	return cmd
}

func newProfileAddCmd(env []string) *cobra.Command {
	var url, caFile, localConfig string
	var local, use bool
	cmd := &cobra.Command{
		Use:   "add <name>",
		Short: "Add a profile for a remote server (or for a local daemon with --local)",
		Long: "Add a profile. A remote profile needs the server's https URL; --ca-file adds a private CA to the system\n" +
			"roots. Sign in with `sm login`. The first profile becomes the current one.",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			profile, err := newProfile(local, url, caFile, localConfig)
			if err != nil {
				return err
			}
			path := profilesFile(env)
			profiles, err := client.LoadProfiles(path)
			if err != nil {
				return err
			}
			if err := profiles.Add(args[0], profile); err != nil {
				return err
			}
			if use {
				if err := profiles.Use(args[0]); err != nil {
					return err
				}
			}
			if err := client.SaveProfiles(path, profiles); err != nil {
				return err
			}
			return emit(cmd, profileRow(profiles, args[0]), func(w io.Writer) error {
				_, err := fmt.Fprintf(w, "added profile %s (%s)\n", args[0], profile.Describe())
				return err
			})
		},
	}
	cmd.Flags().StringVar(&url, "url", "", "server URL, https://host[:port]")
	cmd.Flags().StringVar(&caFile, "ca-file", "", "PEM file with an extra CA to trust (absolute path)")
	cmd.Flags().BoolVar(&local, "local", false, "a local daemon profile instead of a remote one")
	cmd.Flags().StringVar(&localConfig, "config-file", "", "with --local: the daemon's configuration file (default: the standard location)")
	cmd.Flags().BoolVar(&use, "use", false, "make it the current profile")
	return cmd
}

func newProfile(local bool, url, caFile, localConfig string) (client.Profile, error) {
	if local {
		if url != "" || caFile != "" {
			return client.Profile{}, usageErrorf("--local takes no --url or --ca-file")
		}
		return client.Profile{Type: client.ProfileLocal, Config: absolute(localConfig)}, nil
	}
	if url == "" {
		return client.Profile{}, usageErrorf("--url is required (or --local)")
	}
	if localConfig != "" {
		return client.Profile{}, usageErrorf("--config-file only applies with --local")
	}
	origin, err := client.ValidateServerURL(url)
	if err != nil {
		return client.Profile{}, err
	}
	profile := client.Profile{Type: client.ProfileRemote, URL: origin, Auth: client.AuthOIDC, CAFile: absolute(caFile)}
	if _, err := client.NewRemote(client.Remote{URL: profile.URL, CAFile: profile.CAFile}, client.Options{}); err != nil {
		return client.Profile{}, err
	}
	return profile, nil
}

// absolute resolves a user-typed path; "" stays "".
func absolute(path string) string {
	if path == "" {
		return ""
	}
	if abs, err := filepath.Abs(path); err == nil {
		return abs
	}
	return path
}

// profileView is one profile as listed.
type profileView struct {
	Name     string `json:"name"`
	Current  bool   `json:"current"`
	Type     string `json:"type"`
	URL      string `json:"url,omitempty"`
	CAFile   string `json:"ca_file,omitempty"`
	Config   string `json:"config,omitempty"`
	LoggedIn *bool  `json:"logged_in,omitempty"`
}

func profileRow(p *client.Profiles, name string) profileView {
	profile := p.Profiles[name]
	return profileView{
		Name: name, Current: p.Current == name, Type: string(profile.Type),
		URL: profile.URL, CAFile: profile.CAFile, Config: profile.Config,
	}
}

func newProfileListCmd(env []string) *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "List profiles and whether you are signed in to each",
		Args:  noArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			profiles, err := client.LoadProfiles(profilesFile(env))
			if err != nil {
				return err
			}
			store := credentialStore(env)
			views := make([]profileView, 0, len(profiles.Profiles))
			for _, name := range profiles.Names() {
				view := profileRow(profiles, name)
				if view.Type == string(client.ProfileRemote) {
					_, err := store.Get(cmd.Context(), name)
					signedIn := err == nil
					view.LoggedIn = &signedIn
				}
				views = append(views, view)
			}
			return emit(cmd, views, func(w io.Writer) error { return writeProfiles(w, profiles, views) })
		},
	}
}

func writeProfiles(w io.Writer, p *client.Profiles, views []profileView) error {
	rows := make([][]string, len(views))
	for i, v := range views {
		current, signedIn := "", "-"
		if v.Current {
			current = "*"
		}
		if v.LoggedIn != nil {
			signedIn = map[bool]string{true: "yes", false: "no"}[*v.LoggedIn]
		}
		rows[i] = []string{current, v.Name, v.Type, p.Profiles[v.Name].Describe(), signedIn}
	}
	return table(w, []string{"", "NAME", "TYPE", "TARGET", "SIGNED IN"}, rows)
}

func newProfileUseCmd(env []string) *cobra.Command {
	return &cobra.Command{
		Use:   "use <name>",
		Short: "Make a profile the current one",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			path := profilesFile(env)
			profiles, err := client.LoadProfiles(path)
			if err != nil {
				return err
			}
			if err := profiles.Use(args[0]); err != nil {
				return err
			}
			if err := client.SaveProfiles(path, profiles); err != nil {
				return err
			}
			return emit(cmd, profileRow(profiles, args[0]), func(w io.Writer) error {
				_, err := fmt.Fprintf(w, "now using profile %s\n", args[0])
				return err
			})
		},
	}
}

func newProfileRemoveCmd(env []string) *cobra.Command {
	return &cobra.Command{
		Use:   "remove <name>",
		Short: "Remove a profile and its stored credential (sign out first to end the session on the server)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			path := profilesFile(env)
			profiles, err := client.LoadProfiles(path)
			if err != nil {
				return err
			}
			if err := profiles.Remove(args[0]); err != nil {
				return err
			}
			if err := client.SaveProfiles(path, profiles); err != nil {
				return err
			}
			if err := credentialStore(env).Delete(cmd.Context(), args[0]); err != nil {
				return fmt.Errorf("profile removed, but its stored credential could not be deleted: %w", err)
			}
			return emit(cmd, map[string]string{"removed": args[0]}, func(w io.Writer) error {
				_, err := fmt.Fprintf(w, "removed profile %s\n", args[0])
				return err
			})
		},
	}
}
