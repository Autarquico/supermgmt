package systemd

import "strings"

// properties is the output of `systemctl show`: Key=Value lines, where a key
// may repeat (one ExecStart line per entry).
type properties map[string][]string

func parseProps(out string) properties {
	props := properties{}
	for _, line := range strings.Split(out, "\n") {
		key, value, ok := strings.Cut(strings.TrimRight(line, "\r"), "=")
		if ok && key != "" {
			props[key] = append(props[key], value)
		}
	}
	return props
}

// first returns the first value of key, or "" when absent.
func (p properties) first(key string) string {
	if values := p[key]; len(values) > 0 {
		return values[0]
	}
	return ""
}

// nonEmpty returns the values of key that are not empty.
func (p properties) nonEmpty(key string) []string {
	var values []string
	for _, v := range p[key] {
		if strings.TrimSpace(v) != "" {
			values = append(values, v)
		}
	}
	return values
}
