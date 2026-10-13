package installer

import (
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"testing"
)

// Every fake host satisfies Files, so a method added to the port cannot be skipped silently.
var (
	_ Files = (*world)(nil)
	_ Files = (*uhost)(nil)
	_ Files = (*aw)(nil)
	_ Files = diskHost{}
)

// filesPortSources are the files whose host access goes through the Files port alone.
var filesPortSources = []string{"upgrade.go", "upgrade_host.go", "system.go"}

func TestFilesPortIsNeverTypeAsserted(t *testing.T) {
	for _, file := range filesPortSources {
		parsed, err := parser.ParseFile(token.NewFileSet(), file, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		ast.Inspect(parsed, func(n ast.Node) bool {
			assert, ok := n.(*ast.TypeAssertExpr)
			if !ok || assert.Type == nil {
				return true
			}
			if sel, ok := assert.X.(*ast.SelectorExpr); ok && sel.Sel.Name == "Files" {
				t.Errorf("%s asserts a type on Files", file)
			}
			return true
		})
	}
}

type brokenCanonicalFiles struct{ Files }

func (brokenCanonicalFiles) Canonical(string) (string, error) {
	return "", errors.New("no such directory")
}

func TestUpgrade_UnresolvablePathFailsInsteadOfFallingBack(t *testing.T) {
	h := newUHost(t)
	u := &upgrader{d: Deps{Files: brokenCanonicalFiles{h}}, t: upgradeTarget{dbPath: "/var/lib/supermgmt/sm.db"}}
	if _, err := u.lockDatabase(); err == nil {
		t.Fatal("lockDatabase succeeded without a canonical path")
	}
	if len(h.events) != 0 {
		t.Errorf("a lock was attempted: %v", h.events)
	}
}
