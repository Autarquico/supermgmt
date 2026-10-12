package secrets

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
)

// OpenFileKeysReadOnly loads and verifies the keys of an instance that already
// has them. Unlike OpenFileKeys it never creates the keys directory or a first
// KEK: a missing directory, a missing active pointer or a missing key file is a
// *KeysUnavailableError, and nothing on disk or in the repository changes.
func OpenFileKeysReadOnly(ctx context.Context, dir string, repo Repo) (*FileKeys, error) {
	if err := checkExistingDir(dir); err != nil {
		return nil, err
	}
	active, found, err := activeKEK(ctx, repo)
	if err != nil {
		return nil, err
	}
	if !found {
		return nil, &KeysUnavailableError{Problems: []string{"settings." + settingActiveKEK + " is missing: the instance has no keys"}}
	}
	return loadReferenced(ctx, dir, repo, active)
}

func checkExistingDir(dir string) error {
	info, err := os.Lstat(dir)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return &KeysUnavailableError{Problems: []string{"keys dir " + dir + ": does not exist"}}
	case err != nil:
		return fmt.Errorf("stat keys dir: %w", err)
	}
	if problem := dirProblem(info, os.Getuid()); problem != "" {
		return &KeysUnavailableError{Problems: []string{"keys dir " + dir + ": " + problem}}
	}
	return nil
}
