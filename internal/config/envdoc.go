package config

import (
	"errors"
	"fmt"
	"strings"
)

const (
	envTableBegin = "<!-- BEGIN GENERATED ENV TABLE -->"
	envTableEnd   = "<!-- END GENERATED ENV TABLE -->"
)

// EnvTableMarkdown renders the override table for docs/configuration.md.
func EnvTableMarkdown() string {
	var b strings.Builder
	b.WriteString("| Variable | YAML path | Type |\n|---|---|---|\n")
	for _, v := range EnvVars() {
		fmt.Fprintf(&b, "| `%s` | `%s` | %s |\n", v.Name, v.YAMLPath, v.Type)
	}
	return b.String()
}

// ReplaceEnvTable returns doc with the text between the generated-table
// markers replaced by the current override table.
func ReplaceEnvTable(doc string) (string, error) {
	begin := strings.Index(doc, envTableBegin)
	end := strings.Index(doc, envTableEnd)
	if begin < 0 || end < begin {
		return "", errors.New("generated env table markers not found")
	}
	head := doc[:begin+len(envTableBegin)]
	return head + "\n" + EnvTableMarkdown() + doc[end:], nil
}
