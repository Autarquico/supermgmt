package cli

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/autarquico/supermgmt/internal/api/wire"
	"github.com/autarquico/supermgmt/internal/client"
	smerr "github.com/autarquico/supermgmt/internal/errors"
)

const (
	// loginTimeout bounds the browser round trip; the server keeps the
	// login state for 10 minutes (ADR-0018).
	loginTimeout     = 5 * time.Minute
	callbackPath     = "/callback"
	clientName       = "sm"
	verifierBytes    = 32
	slowDownBy       = 5 * time.Second
	maxTokenBytes    = 512
	maxBootstrapCode = 256
	maxDisplayName   = 128
)

// loginDeps are the parts of `sm login` that touch the outside world; tests
// replace them.
type loginDeps struct {
	// openBrowser opens url in the user's browser.
	openBrowser func(ctx context.Context, url string) error
	// sleep waits between device polls.
	sleep func(ctx context.Context, d time.Duration) error
}

func defaultLoginDeps(env []string) loginDeps {
	return loginDeps{openBrowser: browserOpener(env), sleep: sleepContext}
}

func sleepContext(ctx context.Context, d time.Duration) error {
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

// browserOpener starts the platform's URL opener found on the PATH of env. The
// URL is an argument, never a shell string.
func browserOpener(env []string) func(context.Context, string) error {
	return func(ctx context.Context, target string) error {
		program := map[string]string{"darwin": "open", "linux": "xdg-open"}[runtime.GOOS]
		if program == "" {
			return errors.New("no known browser opener on this platform")
		}
		path, ok := client.LookPath(env, program)
		if !ok {
			return fmt.Errorf("%s is not installed", program)
		}
		cmd := exec.CommandContext(ctx, path, target) //nolint:gosec // fixed opener, URL checked by the caller
		cmd.Env = env
		return cmd.Start()
	}
}

type loginFlags struct {
	profile      string
	callbackPort int
	device       bool
	noBrowser    bool
	bootstrap    bool
	tokenStdin   bool
	displayName  string
}

func newLoginCmd(env []string, deps loginDeps) *cobra.Command {
	var f loginFlags
	cmd := &cobra.Command{
		Use:   "login",
		Short: "Sign in to a remote server",
		Long: "Sign in to the server of the current profile with your identity provider. By default a browser opens\n" +
			"and the provider redirects back to a loopback port; --device shows a code to enter on another device.\n" +
			"The session token is kept in the OS credential store (a 0600 file when none is usable), never printed.\n\n" +
			"Providers with a confidential client (such as Dex) need a registered redirect: pass --callback-port.\n" +
			"--bootstrap exchanges the one-time code of `sm admin bootstrap-code` (read from the terminal or stdin);\n" +
			"on a server with OIDC, sign in normally first, then run --bootstrap. Without OIDC the administrator is created\n" +
			"by name: --display-name, or a prompt (prefilled from $USER) on a terminal. --token-stdin stores an API token.",
		Args: noArgs,
		RunE: func(cmd *cobra.Command, _ []string) error { return runLogin(cmd, env, deps, f) },
	}
	cmd.Flags().StringVar(&f.profile, "profile", "", "profile to sign in to (default: the current one)")
	cmd.Flags().IntVar(&f.callbackPort, "callback-port", 0, "loopback port for the browser redirect (default: a random free one)")
	cmd.Flags().BoolVar(&f.device, "device", false, "use the device authorization grant instead of a browser redirect")
	cmd.Flags().BoolVar(&f.noBrowser, "no-browser", false, "print the URL instead of opening a browser")
	cmd.Flags().BoolVar(&f.bootstrap, "bootstrap", false, "exchange a one-time bootstrap code for the first administrator")
	cmd.Flags().StringVar(&f.displayName, "display-name", "", "name of the first administrator (--bootstrap on a server without OIDC)")
	cmd.Flags().BoolVar(&f.tokenStdin, "token-stdin", false, "store an API token read from the terminal or stdin")
	return cmd
}

// loginOutcome is the --json output of a login.
type loginOutcome struct {
	Profile    string     `json:"profile"`
	IdentityID string     `json:"identity_id"`
	Name       string     `json:"display_name"`
	ExpiresAt  *time.Time `json:"expires_at,omitempty"`
	StoredIn   string     `json:"stored_in"`
}

func runLogin(cmd *cobra.Command, env []string, deps loginDeps, f loginFlags) error {
	if exclusive(f.device, f.bootstrap, f.tokenStdin) > 1 {
		return usageErrorf("--device, --bootstrap and --token-stdin are alternatives")
	}
	name, profile, err := loginProfile(cmd, env, f.profile)
	if err != nil {
		return err
	}
	store := credentialStore(env)
	anonymous, err := client.NewRemote(client.Remote{URL: profile.URL, CAFile: profile.CAFile}, client.Options{})
	if err != nil {
		return err
	}
	var token string
	var expires *time.Time
	switch {
	case f.tokenStdin:
		token, err = readToken(cmd)
	case f.bootstrap:
		token, expires, err = bootstrapLogin(cmd, env, store, name, profile, f.displayName)
	case f.device:
		token, expires, err = deviceLogin(cmd, anonymous, deps)
	default:
		token, expires, err = browserLogin(cmd, anonymous, deps, f)
	}
	if err != nil {
		return err
	}
	return finishLogin(cmd, env, store, name, profile, token, expires, f.tokenStdin)
}

func exclusive(flags ...bool) int {
	n := 0
	for _, f := range flags {
		if f {
			n++
		}
	}
	return n
}

// loginProfile finds the remote profile to sign in to.
func loginProfile(cmd *cobra.Command, env []string, flagged string) (string, client.Profile, error) {
	profiles, err := client.LoadProfiles(profilesFile(env))
	if err != nil {
		return "", client.Profile{}, err
	}
	name := flagged
	if name == "" {
		name = profiles.Current
	}
	profile, ok := profiles.Profiles[name]
	switch {
	case name == "" || !ok && flagged == "":
		return "", client.Profile{}, usageErrorf("no profile selected: add one with `sm profile add NAME --url https://...`")
	case !ok:
		return "", client.Profile{}, smerr.New(smerr.CodeNotFound, "", fmt.Sprintf("no profile named %q", name))
	case profile.Type != client.ProfileRemote:
		return "", client.Profile{}, usageErrorf("profile %s is local: nothing to sign in to", name)
	}
	return name, profile, nil
}

// finishLogin stores the token, confirms who it belongs to and reports.
func finishLogin(cmd *cobra.Command, env []string, store client.CredentialStore, name string, profile client.Profile, token string, expires *time.Time, apiToken bool) error {
	ctx := cmd.Context()
	signed, err := client.NewRemote(client.Remote{URL: profile.URL, CAFile: profile.CAFile, Token: token}, client.Options{})
	if err != nil {
		return err
	}
	me, err := signed.Me(ctx)
	if err != nil {
		return fmt.Errorf("the server did not accept the credential: %w", err)
	}
	location, err := store.Set(ctx, name, token)
	if err != nil {
		return fmt.Errorf("store the credential of profile %s: %w", name, err)
	}
	if apiToken {
		if err := recordAuth(env, name, profile, client.AuthToken); err != nil {
			return err
		}
	}
	out := loginOutcome{Profile: name, IdentityID: string(me.IdentityID), Name: me.DisplayName, ExpiresAt: expires, StoredIn: location}
	return emit(cmd, out, func(w io.Writer) error {
		_, err := fmt.Fprintf(w, "signed in to %s as %s (%s)\ncredential kept in %s\n", name, me.DisplayName, me.IdentityID, location)
		return err
	})
}

func recordAuth(env []string, name string, profile client.Profile, auth string) error {
	path := profilesFile(env)
	profiles, err := client.LoadProfiles(path)
	if err != nil {
		return err
	}
	profile.Auth = auth
	if err := profiles.Set(name, profile); err != nil {
		return err
	}
	return client.SaveProfiles(path, profiles)
}

func readToken(cmd *cobra.Command) (string, error) {
	return readSecret(cmd, secretInput{prompt: "API token: ", limit: maxTokenBytes})
}

// ---- browser flow (RFC 8252 loopback, PKCE S256) ------------------------------------

func browserLogin(cmd *cobra.Command, api *client.Client, deps loginDeps, f loginFlags) (string, *time.Time, error) {
	ctx := cmd.Context()
	verifier, challenge, err := newPKCE()
	if err != nil {
		return "", nil, err
	}
	listener, err := (&net.ListenConfig{}).Listen(ctx, "tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(f.callbackPort)))
	if err != nil {
		return "", nil, usageErrorf("cannot listen on 127.0.0.1:%d for the redirect: %v", f.callbackPort, err)
	}
	redirect := "http://" + listener.Addr().String() + callbackPath
	started, err := api.OIDCStart(ctx, wire.OIDCStartRequest{RedirectURI: redirect, CodeChallenge: challenge})
	if err != nil {
		_ = listener.Close()
		return "", nil, err
	}
	waiting := awaitCallback(listener)
	defer waiting.stop()

	announceLogin(cmd, deps, started.AuthorizationURL, f.noBrowser)
	waitCtx, cancel := context.WithTimeout(ctx, loginTimeout)
	defer cancel()
	code, state, err := waiting.result(waitCtx)
	if err != nil {
		return "", nil, err
	}
	if subtle.ConstantTimeCompare([]byte(state), []byte(started.State)) != 1 {
		return "", nil, smerr.New(smerr.CodeUnauthenticated, "", "the redirect carried a state this login did not start: it was ignored")
	}
	session, err := api.OIDCExchange(ctx, wire.OIDCExchangeRequest{Code: code, State: state, CodeVerifier: verifier, Client: clientName})
	if err != nil {
		return "", nil, err
	}
	return session.Token, &session.ExpiresAt, nil
}

// announceLogin prints the URL and, unless told not to, opens the browser.
func announceLogin(cmd *cobra.Command, deps loginDeps, authURL string, noBrowser bool) {
	ctx := cmd.Context()
	errOut := cmd.ErrOrStderr()
	_, _ = fmt.Fprintf(errOut, "Open this URL to sign in:\n  %s\n", authURL)
	if noBrowser || !isWebURL(authURL) {
		return
	}
	if err := deps.openBrowser(ctx, authURL); err != nil {
		_, _ = fmt.Fprintf(errOut, "(could not open a browser: %v)\n", err)
	}
}

func isWebURL(raw string) bool {
	u, err := url.Parse(raw)
	return err == nil && (u.Scheme == "https" || u.Scheme == "http") && u.Host != ""
}

func newPKCE() (verifier, challenge string, err error) {
	raw := make([]byte, verifierBytes)
	if _, err := rand.Read(raw); err != nil {
		return "", "", fmt.Errorf("generate the PKCE verifier: %w", err)
	}
	verifier = base64.RawURLEncoding.EncodeToString(raw)
	sum := sha256.Sum256([]byte(verifier))
	return verifier, base64.RawURLEncoding.EncodeToString(sum[:]), nil
}

// callbackServer receives the redirect of the identity provider on loopback.
type callbackServer struct {
	server  *http.Server
	results chan callbackResult
}

type callbackResult struct {
	code, state string
	err         error
}

func awaitCallback(listener net.Listener) *callbackServer {
	c := &callbackServer{results: make(chan callbackResult, 1)}
	mux := http.NewServeMux()
	mux.HandleFunc("GET "+callbackPath, c.handle)
	c.server = &http.Server{Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	go func() { _ = c.server.Serve(listener) }()
	return c
}

func (c *callbackServer) handle(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	result := callbackResult{code: q.Get("code"), state: q.Get("state")}
	switch {
	case q.Get("error") != "":
		result.err = smerr.New(smerr.CodeUnauthenticated, "", "the identity provider refused the login: "+q.Get("error"))
	case result.code == "" || result.state == "":
		http.Error(w, "missing code or state", http.StatusBadRequest)
		return
	}
	select {
	case c.results <- result:
	default: // a second redirect is ignored
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	_, _ = io.WriteString(w, "SuperMgmt: you can close this window and return to the terminal.\n")
}

func (c *callbackServer) result(ctx context.Context) (code, state string, err error) {
	select {
	case r := <-c.results:
		return r.code, r.state, r.err
	case <-ctx.Done():
		return "", "", smerr.New(smerr.CodeTimeout, "", "no redirect arrived: the login timed out")
	}
}

func (c *callbackServer) stop() {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	_ = c.server.Shutdown(ctx)
}

// ---- device flow -----------------------------------------------------------------------

func deviceLogin(cmd *cobra.Command, api *client.Client, deps loginDeps) (string, *time.Time, error) {
	ctx := cmd.Context()
	started, err := api.DeviceStart(ctx)
	if err != nil {
		return "", nil, err
	}
	errOut := cmd.ErrOrStderr()
	uri := started.VerificationURI
	if started.VerificationURIComplete != "" {
		uri = started.VerificationURIComplete
	}
	_, _ = fmt.Fprintf(errOut, "On any device, open:\n  %s\nand enter the code  %s\n", started.VerificationURI, started.UserCode)
	if uri != started.VerificationURI {
		_, _ = fmt.Fprintf(errOut, "(or open %s directly)\n", uri)
	}
	ctx, cancel := context.WithDeadline(ctx, started.ExpiresAt)
	defer cancel()
	interval := time.Duration(max(started.IntervalSeconds, 1)) * time.Second
	for {
		if err := deps.sleep(ctx, interval); err != nil {
			return "", nil, deviceWaitError(ctx, err)
		}
		polled, err := api.DevicePoll(ctx, wire.DevicePollRequest{TransactionID: started.TransactionID, Client: clientName})
		if err != nil {
			return "", nil, deviceWaitError(ctx, err)
		}
		switch polled.Status {
		case wire.DeviceComplete:
			if polled.Session == nil {
				return "", nil, smerr.New(smerr.CodeInternal, "", "the server completed the login without a session")
			}
			return polled.Session.Token, &polled.Session.ExpiresAt, nil
		case wire.DeviceSlowDown:
			interval += slowDownBy
		case wire.DevicePending:
		default:
			return "", nil, smerr.New(smerr.CodeInternal, "", fmt.Sprintf("the server answered an unknown device status %q", polled.Status))
		}
	}
}

func deviceWaitError(ctx context.Context, err error) error {
	if errors.Is(ctx.Err(), context.DeadlineExceeded) {
		return smerr.New(smerr.CodeTimeout, "", "the device code expired before you entered it: run `sm login --device` again")
	}
	return err
}

// ---- bootstrap ---------------------------------------------------------------------------

// bootstrapLogin exchanges the one-time code (spec §11.5). A session this
// profile already holds travels with it: on a server with OIDC that session
// is the identity that becomes the administrator.
func bootstrapLogin(cmd *cobra.Command, env []string, store client.CredentialStore, name string, profile client.Profile, displayName string) (string, *time.Time, error) {
	ctx := cmd.Context()
	held, _ := store.Get(ctx, name)
	api, err := client.NewRemote(client.Remote{URL: profile.URL, CAFile: profile.CAFile, Token: held}, client.Options{})
	if err != nil {
		return "", nil, err
	}
	if held == "" && displayName == "" { // no session: the server has no OIDC and must be told who the admin is
		if displayName, err = askDisplayName(cmd, envMap(env)["USER"]); err != nil {
			return "", nil, err
		}
	}
	code, err := readSecret(cmd, secretInput{prompt: "Bootstrap code: ", limit: maxBootstrapCode})
	if err != nil {
		return "", nil, err
	}
	issued, err := api.Bootstrap(ctx, wire.BootstrapRequest{Code: code, DisplayName: displayName})
	switch {
	case err != nil:
		return "", nil, err
	case issued.Session != nil:
		return issued.Session.Token, &issued.Session.ExpiresAt, nil
	case issued.APIToken != nil:
		return issued.APIToken.Value, &issued.APIToken.Token.ExpiresAt, nil
	}
	if held != "" {
		return held, nil, nil // the held session is now the administrator's
	}
	return "", nil, smerr.New(smerr.CodeInternal, "", "the server accepted the code but issued no credential")
}

// askDisplayName prompts on a terminal, offering suggested; anywhere else the
// name must come from --display-name.
func askDisplayName(cmd *cobra.Command, suggested string) (string, error) {
	tty, ok := cmd.InOrStdin().(*os.File)
	if !ok || !isTerminal(tty) {
		return "", usageErrorf("--display-name is required when the server has no OIDC: it names the first administrator")
	}
	prompt := "Administrator display name: "
	if suggested != "" {
		prompt = fmt.Sprintf("Administrator display name [%s]: ", suggested)
	}
	answer, err := promptLine(tty, cmd.ErrOrStderr(), prompt)
	if err != nil {
		return "", err
	}
	if answer = strings.TrimSpace(answer); answer == "" {
		answer = suggested
	}
	if answer == "" || len(answer) > maxDisplayName {
		return "", usageErrorf("the display name must be 1 to %d bytes", maxDisplayName)
	}
	return answer, nil
}

// ---- sm logout ------------------------------------------------------------------------------

func newLogoutCmd(env []string) *cobra.Command {
	var profileFlag string
	cmd := &cobra.Command{
		Use:   "logout",
		Short: "Sign out: revoke the session on the server and forget the stored credential",
		Args:  noArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			name, profile, err := loginProfile(cmd, env, profileFlag)
			if err != nil {
				return err
			}
			store := credentialStore(env)
			ctx := cmd.Context()
			token, err := store.Get(ctx, name)
			if errors.Is(err, client.ErrNoCredential) {
				return emit(cmd, map[string]any{"profile": name, "signed_out": false}, func(w io.Writer) error {
					_, err := fmt.Fprintf(w, "not signed in to %s\n", name)
					return err
				})
			}
			if err != nil {
				return err
			}
			revoked := revokeSession(ctx, profile, token)
			if err := store.Delete(ctx, name); err != nil {
				return fmt.Errorf("forget the stored credential: %w", err)
			}
			return emit(cmd, map[string]any{"profile": name, "signed_out": true, "revoked_on_server": revoked == nil}, func(w io.Writer) error {
				if revoked != nil {
					_, _ = fmt.Fprintf(cmd.ErrOrStderr(), "warning: the server could not revoke the session (%v); it expires on its own\n", revoked)
				}
				_, err := fmt.Fprintf(w, "signed out of %s\n", name)
				return err
			})
		},
	}
	cmd.Flags().StringVar(&profileFlag, "profile", "", "profile to sign out of (default: the current one)")
	return cmd
}

// revokeSession asks the server to end the session. The credential is
// forgotten locally either way.
func revokeSession(ctx context.Context, profile client.Profile, token string) error {
	api, err := client.NewRemote(client.Remote{URL: profile.URL, CAFile: profile.CAFile, Token: token}, client.Options{})
	if err != nil {
		return err
	}
	return api.Logout(ctx)
}
