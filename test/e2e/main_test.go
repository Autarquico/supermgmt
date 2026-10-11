//go:build e2e

package e2e_test

import (
	"fmt"
	"os"
	"testing"

	"github.com/autarquico/supermgmt/test/e2e/harness"
)

func TestMain(m *testing.M) {
	if err := harness.Init(); err != nil {
		fmt.Fprintln(os.Stderr, "e2e init:", err)
		os.Exit(1)
	}
	code := m.Run()
	harness.Close()
	os.Exit(code)
}
