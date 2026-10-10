package policy

import (
	_ "embed"
	"fmt"
	"sync"
)

//go:embed default.yaml
var defaultYAML []byte

var defaultPolicy = sync.OnceValues(func() (*Policy, error) {
	p, err := Parse(defaultYAML)
	if err != nil {
		return nil, fmt.Errorf("built-in default policy: %w", err)
	}
	return p, nil
})

// DefaultYAML returns the embedded built-in policy text (`sm config show --policy`).
func DefaultYAML() []byte { return append([]byte(nil), defaultYAML...) }

// Default returns the built-in default policy (spec §11.2).
func Default() (*Policy, error) { return defaultPolicy() }
