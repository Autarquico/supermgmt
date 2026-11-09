package cli

import (
	"context"
	"errors"
	"testing"

	"github.com/spf13/cobra"

	"github.com/autarquico/supermgmt/internal/assistant"
	"github.com/autarquico/supermgmt/internal/client"
)

func (r *asstRig) launcher(env []string) *assistant.Launcher {
	deps := assistantDeps{
		connect:     func(*cobra.Command) (assistantAPI, target, error) { return r.api, r.where, nil },
		nativeStore: func() (client.CredentialStore, bool) { return asstStore{}, r.keychain },
		executable:  func() (string, error) { return "/usr/local/bin/sm", nil },
		newSession: func(cfg assistant.Config) (assistant.Conversation, error) {
			r.cfg, r.launched = cfg, true
			return r.session, nil
		},
		claudeAvailable: func() error { return r.claudeErr },
	}
	return assistantLauncher(env, deps, r.api, r.where, defaultAssistantClient, assistant.AuthSubscription)
}

func TestAssistantLauncherRefusesWithTheTextOfTheCommand(t *testing.T) {
	r := newAsstRig()
	r.api.clients = nil
	_, want := r.run(t, "", nil)
	_, got := r.launcher([]string{"HOME=" + t.TempDir()}).Check(context.Background())
	if want == nil || got == nil || got.Error() != want.Error() {
		t.Fatalf("launcher error = %v, command error = %v", got, want)
	}
	if r.launched {
		t.Fatal("a refused check launched a session")
	}
}

func TestAssistantLauncherChecksClaudeThenStartsTheSession(t *testing.T) {
	r := newAsstRig()
	r.claudeErr = assistant.ErrClaudeNotFound
	l := r.launcher(nil)
	if _, err := l.Check(context.Background()); !errors.Is(err, assistant.ErrClaudeNotFound) || r.api.listed != 0 {
		t.Fatalf("err=%v listed=%d", err, r.api.listed)
	}
	r.claudeErr = nil
	id, err := l.Check(context.Background())
	if err != nil || id.ClientName != "assistant" || id.ClientID != asstIdentity || id.Instance != "the local daemon" {
		t.Fatalf("identity = %+v err=%v", id, err)
	}
	conv, err := l.Start(context.Background())
	if err != nil || conv == nil || !r.launched || r.cfg.SMBinary != "/usr/local/bin/sm" {
		t.Fatalf("conv=%v err=%v cfg=%+v", conv, err, r.cfg)
	}
}

func TestValidateAssistantAuth(t *testing.T) {
	if _, err := validateAssistantAuth(nil, "x"); err == nil {
		t.Fatal("unknown auth accepted")
	}
	if _, err := validateAssistantAuth(nil, "api-key"); err == nil {
		t.Fatal("api-key without a key accepted")
	}
	if auth, err := validateAssistantAuth([]string{"ANTHROPIC_API_KEY=k"}, "api-key"); err != nil || auth != assistant.AuthAPIKey {
		t.Fatalf("auth=%v err=%v", auth, err)
	}
}
