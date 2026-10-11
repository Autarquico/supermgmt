//go:build !darwin && !linux

package cli

import "errors"

// disableEcho is unavailable here: a secret can only be piped on stdin.
func disableEcho(int) (func(), error) {
	return nil, errors.New("this platform cannot turn off terminal echo")
}
