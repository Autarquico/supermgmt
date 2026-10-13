package client_test

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/autarquico/supermgmt/internal/client"
)

func TestNativeStoreIsAbsentWithoutAnOSTool(t *testing.T) {
	empty := []string{"PATH=" + t.TempDir()}
	for _, goos := range []string{"darwin", "linux", "windows"} {
		store, ok := client.OpenNativeCredentialStore(goos, empty)
		if ok || store != nil {
			t.Errorf("%s: got store %v, ok=%v, want none", goos, store, ok)
		}
	}
}

func TestNativeStoreFindsTheToolOfThePlatformOnly(t *testing.T) {
	tb := newToolbox(t, "secret-tool", fakeSecretTool)

	if _, ok := client.OpenNativeCredentialStore("darwin", tb.env()); ok {
		t.Error("secret-tool must not serve darwin")
	}
	store, ok := client.OpenNativeCredentialStore("linux", tb.env())
	if !ok {
		t.Fatal("secret-tool on PATH was not found")
	}
	if _, err := store.Set(context.Background(), "claude-desktop", testToken); err != nil {
		t.Fatal(err)
	}
	if got, err := store.Get(context.Background(), "claude-desktop"); err != nil || got != testToken {
		t.Errorf("Get = %q, %v", got, err)
	}
}

func TestNativeStoreReportsAToolFailureInsteadOfFallingBackToAFile(t *testing.T) {
	tb := newToolbox(t, "secret-tool", brokenTool)
	store, ok := client.OpenNativeCredentialStore("linux", tb.env())
	if !ok {
		t.Fatal("tool not found")
	}

	location, err := store.Set(context.Background(), "claude-desktop", testToken)

	if err == nil || location != "" {
		t.Fatalf("Set = %q, %v, want a failure", location, err)
	}
	if strings.Contains(err.Error(), testToken) {
		t.Errorf("error carries the token: %v", err)
	}
	if _, err := store.Get(context.Background(), "claude-desktop"); !errors.Is(err, client.ErrNoCredential) {
		t.Errorf("Get after a failed Set: %v", err)
	}
}
