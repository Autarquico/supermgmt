package cli

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/autarquico/supermgmt/internal/audit"
	"github.com/autarquico/supermgmt/internal/client"
)

// maxTokenFileBytes bounds what is read from a token source: tokens are short.
const maxTokenFileBytes = 4 << 10

// readTokenFile reads an MCP client token from a regular file that only its
// owner can touch. A symlink is refused rather than followed.
func readTokenFile(path string, euid int) (audit.Secret, error) {
	file, err := os.OpenFile(filepath.Clean(path), os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return "", usageErrorf("--token-file: %s", err)
	}
	defer func() { _ = file.Close() }()
	if err := checkTokenFile(file, euid); err != nil {
		return "", err
	}
	raw, err := io.ReadAll(io.LimitReader(file, maxTokenFileBytes))
	if err != nil {
		return "", usageErrorf("--token-file: %s", err)
	}
	return tokenFromText("--token-file", string(raw))
}

// readKeychainToken reads an MCP client token from the native OS keychain.
func readKeychainToken(ctx context.Context, store client.CredentialStore, name string) (audit.Secret, error) {
	text, err := store.Get(ctx, name)
	if err != nil {
		return "", usageErrorf("--keychain: cannot read entry %q: %s", name, err)
	}
	return tokenFromText("--keychain", text)
}

func tokenFromText(source, text string) (audit.Secret, error) {
	token := strings.TrimSpace(text)
	if token == "" {
		return "", usageErrorf("%s: the token is empty", source)
	}
	if strings.ContainsAny(token, " \t\r\n") {
		return "", usageErrorf("%s: the token must be a single word", source)
	}
	return audit.Secret(token), nil
}
