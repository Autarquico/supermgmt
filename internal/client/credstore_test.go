package client_test

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/autarquico/supermgmt/internal/client"
)

const testToken = "sm1_AbCdEfGhIjKlMnOpQrStUvWxYz0123456789-_AbCdEf"

// toolbox is a directory of fake OS credential tools that log every call.
type toolbox struct {
	dir, log string
}

const fakeSecurity = `#!/bin/sh
printf '%s\n' "$@" >> "LOG/argv"
case "$1" in
-i)
  IFS= read -r line
  printf '%s\n' "$line" > "LOG/stdin"
  tok=${line#* -w \"}
  tok=${tok%\"}
  printf '%s' "$tok" > "LOG/secret"
  ;;
find-generic-password)
  [ -f "LOG/secret" ] || exit 44
  read -r tok < "LOG/secret"
  printf '%s\n' "$tok"
  ;;
delete-generic-password)
  /bin/rm -f "LOG/secret"
  ;;
esac
`

const fakeSecretTool = `#!/bin/sh
printf '%s\n' "$@" >> "LOG/argv"
case "$1" in
store)
  IFS= read -r tok
  printf '%s' "$tok" > "LOG/stdin"
  printf '%s' "$tok" > "LOG/secret"
  ;;
lookup)
  [ -f "LOG/secret" ] || exit 1
  read -r tok < "LOG/secret"
  printf '%s' "$tok"
  ;;
clear)
  /bin/rm -f "LOG/secret"
  ;;
esac
`

const brokenTool = "#!/bin/sh\nprintf '%s\\n' \"$@\" >> \"LOG/argv\"\nexit 1\n"

func newToolbox(t *testing.T, name, script string) toolbox {
	t.Helper()
	tb := toolbox{dir: t.TempDir(), log: t.TempDir()}
	body := strings.ReplaceAll(script, "LOG", tb.log)
	if err := os.WriteFile(filepath.Join(tb.dir, name), []byte(body), 0o755); err != nil {
		t.Fatal(err)
	}
	return tb
}

func (tb toolbox) env() []string { return []string{"PATH=" + tb.dir} }

func (tb toolbox) logged(name string) string {
	data, _ := os.ReadFile(filepath.Join(tb.log, name))
	return string(data)
}

func TestKeychainTokenGoesInOnStdinNeverInArguments(t *testing.T) {
	tb := newToolbox(t, "security", fakeSecurity)
	configDir := t.TempDir()
	store := client.OpenCredentialStore("darwin", tb.env(), configDir)

	location, err := store.Set(context.Background(), "home", testToken)

	if err != nil || !strings.Contains(location, "keychain") {
		t.Fatalf("Set = %q, %v", location, err)
	}
	if strings.Contains(tb.logged("argv"), testToken) {
		t.Errorf("the token reached an argument list:\n%s", tb.logged("argv"))
	}
	if !strings.Contains(tb.logged("stdin"), testToken) || !strings.HasPrefix(tb.logged("stdin"), "add-generic-password") {
		t.Errorf("stdin = %q, want the add command carrying the token", tb.logged("stdin"))
	}
	if _, err := os.Stat(filepath.Join(configDir, "credentials.json")); err == nil {
		t.Errorf("the token was also written to a file")
	}
	got, err := store.Get(context.Background(), "home")
	if err != nil || got != testToken {
		t.Errorf("Get = %q, %v", got, err)
	}
	if strings.Contains(tb.logged("argv"), testToken) {
		t.Errorf("reading the token put it in an argument list")
	}
}

func TestSecretToolTokenGoesInOnStdinNeverInArguments(t *testing.T) {
	tb := newToolbox(t, "secret-tool", fakeSecretTool)
	store := client.OpenCredentialStore("linux", tb.env(), t.TempDir())

	location, err := store.Set(context.Background(), "home", testToken)

	if err != nil || !strings.Contains(location, "secret-tool") {
		t.Fatalf("Set = %q, %v", location, err)
	}
	if strings.Contains(tb.logged("argv"), testToken) || tb.logged("stdin") != testToken {
		t.Errorf("argv:\n%s\nstdin: %q", tb.logged("argv"), tb.logged("stdin"))
	}
	if got, err := store.Get(context.Background(), "home"); err != nil || got != testToken {
		t.Errorf("Get = %q, %v", got, err)
	}
	if err := store.Delete(context.Background(), "home"); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Get(context.Background(), "home"); !errors.Is(err, client.ErrNoCredential) {
		t.Errorf("Get after Delete: %v", err)
	}
}

func TestAFailingOSStoreFallsBackToAnOwnerOnlyFile(t *testing.T) {
	tb := newToolbox(t, "secret-tool", brokenTool) // e.g. no D-Bus session on a headless host
	configDir := filepath.Join(t.TempDir(), "supermgmt")
	store := client.OpenCredentialStore("linux", tb.env(), configDir)

	location, err := store.Set(context.Background(), "home", testToken)

	if err != nil || !strings.Contains(location, "mode 0600") {
		t.Fatalf("Set = %q, %v", location, err)
	}
	file := filepath.Join(configDir, "credentials.json")
	assertMode(t, file, 0o600)
	assertMode(t, configDir, 0o700)
	if got, err := store.Get(context.Background(), "home"); err != nil || got != testToken {
		t.Errorf("Get = %q, %v", got, err)
	}
	if err := store.Delete(context.Background(), "home"); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Get(context.Background(), "home"); !errors.Is(err, client.ErrNoCredential) {
		t.Errorf("Get after Delete: %v", err)
	}
}

func TestWithoutAnyOSToolTheFileStoreIsUsed(t *testing.T) {
	for _, goos := range []string{runtime.GOOS, "darwin", "linux", "plan9"} {
		configDir := t.TempDir()
		store := client.OpenCredentialStore(goos, []string{"PATH=" + t.TempDir()}, configDir)
		if _, err := store.Get(context.Background(), "home"); !errors.Is(err, client.ErrNoCredential) {
			t.Fatalf("%s: Get on an empty store: %v", goos, err)
		}
		if _, err := store.Set(context.Background(), "home", testToken); err != nil {
			t.Fatalf("%s: %v", goos, err)
		}
		assertMode(t, filepath.Join(configDir, "credentials.json"), 0o600)
	}
}

func TestOneProfilesTokenDoesNotTouchAnothers(t *testing.T) {
	store := client.OpenCredentialStore("plan9", nil, t.TempDir())
	ctx := context.Background()
	other := "sm1_ZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZ"
	_, _ = store.Set(ctx, "home", testToken)
	_, _ = store.Set(ctx, "work", other)

	_ = store.Delete(ctx, "home")

	if got, err := store.Get(ctx, "work"); err != nil || got != other {
		t.Errorf("work = %q, %v", got, err)
	}
	if err := store.Delete(ctx, "ghost"); err != nil {
		t.Errorf("deleting an unknown profile: %v", err)
	}
}

func TestATokenOfUnexpectedShapeNeverReachesTheOSTool(t *testing.T) {
	tb := newToolbox(t, "security", fakeSecurity)
	store := client.OpenCredentialStore("darwin", tb.env(), t.TempDir())

	// A quote or a line break could end the add command early and smuggle another.
	hostile := "sm1_x\"\nadd-generic-password -s evil"
	if _, err := store.Set(context.Background(), "home", hostile); err != nil {
		t.Fatal(err)
	}

	if tb.logged("argv") != "" || tb.logged("stdin") != "" {
		t.Errorf("the OS tool was called with a hostile token: argv %q stdin %q", tb.logged("argv"), tb.logged("stdin"))
	}
}

func TestANativeStoreReplacesAStaleFileCopy(t *testing.T) {
	broken := newToolbox(t, "security", brokenTool)
	configDir := t.TempDir()
	ctx := context.Background()
	if _, err := client.OpenCredentialStore("darwin", broken.env(), configDir).Set(ctx, "home", "sm1_stale-token-in-the-file"); err != nil {
		t.Fatal(err)
	}
	working := newToolbox(t, "security", fakeSecurity)

	store := client.OpenCredentialStore("darwin", working.env(), configDir)
	if _, err := store.Set(ctx, "home", testToken); err != nil {
		t.Fatal(err)
	}

	data, _ := os.ReadFile(filepath.Join(configDir, "credentials.json"))
	if strings.Contains(string(data), "stale") {
		t.Errorf("the old file copy is still there: %s", data)
	}
}

func TestACorruptCredentialsFileIsAnErrorNotASilentReset(t *testing.T) {
	configDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(configDir, "credentials.json"), []byte("{broken"), 0o600); err != nil {
		t.Fatal(err)
	}
	store := client.OpenCredentialStore("plan9", nil, configDir)

	if _, err := store.Set(context.Background(), "home", testToken); err == nil {
		t.Error("Set overwrote a credentials file it could not read")
	}
}

func TestLookPathSearchesTheGivenPathAndIgnoresRelativeEntries(t *testing.T) {
	dir := t.TempDir()
	tool := filepath.Join(dir, "mytool")
	if err := os.WriteFile(tool, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	notExecutable := filepath.Join(dir, "plain")
	if err := os.WriteFile(notExecutable, nil, 0o600); err != nil {
		t.Fatal(err)
	}

	if got, ok := client.LookPath([]string{"PATH=relative:" + dir}, "mytool"); !ok || got != tool {
		t.Errorf("LookPath = %q, %v", got, ok)
	}
	if _, ok := client.LookPath([]string{"PATH=" + dir}, "plain"); ok {
		t.Error("a file without the execute bit was found")
	}
	if _, ok := client.LookPath([]string{"HOME=/x"}, "mytool"); ok {
		t.Error("found a tool without a PATH")
	}
}
