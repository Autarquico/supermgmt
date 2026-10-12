package proxmox

import (
	"strconv"
	"strings"
)

// SupportedMajor is the only Proxmox VE major version M3 supports (ADR-0023).
const SupportedMajor = 9

// Supported reports whether the server runs Proxmox VE 9.x.
func (v Version) Supported() bool {
	major, _, _ := strings.Cut(v.Version, ".")
	n, err := strconv.Atoi(major)
	return err == nil && n == SupportedMajor
}
