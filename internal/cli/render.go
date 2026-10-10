package cli

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"
)

func writeJSON(w io.Writer, v any) error {
	return json.NewEncoder(w).Encode(v)
}

func verdict(problems []string) string {
	if len(problems) == 0 {
		return "valid"
	}
	return "invalid"
}

func writeValidateReport(w io.Writer, r validateReport, asJSON bool) error {
	if asJSON {
		return writeJSON(w, r)
	}
	var b strings.Builder
	fmt.Fprintf(&b, "config: %s: %s\n", r.Config.Path, verdict(r.Config.Problems))
	writeLines(&b, "  - ", r.Config.Problems)
	writeLines(&b, "  warning: ", r.Config.Warnings)
	if p := r.Policy; p != nil {
		fmt.Fprintf(&b, "policy: %s: %s", p.Source, verdict(p.Problems))
		if len(p.Problems) == 0 {
			fmt.Fprintf(&b, " (%d rules)", p.Rules)
		}
		b.WriteString("\n")
		writeLines(&b, "  - ", p.Problems)
		writePolicyDiff(&b, p.Diff)
	}
	_, err := io.WriteString(w, b.String())
	return err
}

func writePolicyDiff(b *strings.Builder, d *policyDiff) {
	switch {
	case d == nil:
		return
	case d.empty():
		b.WriteString("  no differences from the built-in default\n")
		return
	}
	b.WriteString("  differences from the built-in default:\n")
	writeLines(b, "    + added rule ", quoteAll(d.Added))
	writeLines(b, "    - removed rule ", quoteAll(d.Removed))
	writeLines(b, "    ~ changed rule ", quoteAll(d.Changed))
}

func quoteAll(names []string) []string {
	out := make([]string, len(names))
	for i, n := range names {
		out[i] = fmt.Sprintf("%q", n)
	}
	return out
}

func writeLines(b *strings.Builder, prefix string, lines []string) {
	for _, line := range lines {
		b.WriteString(prefix + line + "\n")
	}
}
