package cli

import (
	"context"
	"fmt"

	"github.com/autarquico/supermgmt/internal/assistant"
)

// validateAssistantAuth checks --auth and, for api-key, that the key is in the
// environment, before anything is started.
func validateAssistantAuth(env []string, flag string) (assistant.Auth, error) {
	auth := assistant.Auth(flag)
	if auth != assistant.AuthSubscription && auth != assistant.AuthAPIKey {
		return "", usageErrorf("--auth must be subscription or api-key, not %q", flag)
	}
	if auth == assistant.AuthAPIKey && envMap(env)[envAnthropicKey] == "" {
		return "", usageErrorf("--auth api-key needs %s in the environment", envAnthropicKey)
	}
	return auth, nil
}

// assistantSetup is one assistant client on one target: what `sm assistant`
// and the TUI both need to check the registration and launch the session.
type assistantSetup struct {
	env        []string
	deps       assistantDeps
	api        assistantAPI
	where      target
	clientName string
	auth       assistant.Auth
}

// identity finds the registered client and its token, or explains the command to run.
func (s assistantSetup) identity(ctx context.Context) (assistant.Identity, error) {
	token := assistantTokenAt(s.env, s.deps, s.clientName, s.where)
	me, err := requireAssistantClient(ctx, s.api, s.clientName, token, s.where)
	if err != nil {
		return assistant.Identity{}, err
	}
	if err := token.exists(ctx, s.deps, s.clientName, s.where.remote != nil); err != nil {
		return assistant.Identity{}, err
	}
	return assistant.Identity{ClientName: me.Name, ClientID: me.IdentityID, Instance: instanceLabel(s.where), Auth: s.auth}, nil
}

// start launches the session; on failure nothing is left running.
func (s assistantSetup) start(ctx context.Context) (assistant.Conversation, error) {
	exe, err := s.deps.executable()
	if err != nil {
		return nil, fmt.Errorf("locate the sm executable: %w", err)
	}
	token := assistantTokenAt(s.env, s.deps, s.clientName, s.where)
	session, err := s.deps.newSession(assistant.Config{
		Auth: s.auth, SMBinary: exe, Token: token.location(), Target: assistantTarget(s.where, s.env), Env: s.env,
	})
	if err != nil {
		return nil, err
	}
	if err := session.Start(ctx); err != nil {
		_ = session.Close()
		return nil, err
	}
	return session, nil
}

// assistantLauncher is what the TUI is given to run a conversation: the same
// refusals as `sm assistant`, with the same text, and the same session.
func assistantLauncher(env []string, deps assistantDeps, api assistantAPI, where target, clientName string, auth assistant.Auth) *assistant.Launcher {
	setup := assistantSetup{env: env, deps: deps, api: api, where: where, clientName: clientName, auth: auth}
	return &assistant.Launcher{
		Check: func(ctx context.Context) (assistant.Identity, error) {
			if err := deps.claudeAvailable(); err != nil {
				return assistant.Identity{}, err
			}
			return setup.identity(ctx)
		},
		Start: setup.start,
	}
}
