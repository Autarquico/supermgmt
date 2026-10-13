package compose

import (
	"encoding/json"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"unicode"
)

// exemptibleCapabilities is the fixed set of capabilities an admin may
// approve for cap_add (spec §20.3 step 7). An exception naming any other
// capability never takes effect.
var exemptibleCapabilities = []string{
	"NET_BIND_SERVICE", "CHOWN", "SETUID", "SETGID", "DAC_OVERRIDE", "FOWNER", "KILL",
}

const exemptibleSysctlPrefix = "net."

// The four checks below are the only way a key outside the closed service
// schema (step 5) can appear: each admits exactly the values the app's
// exceptions list for this service, nothing more.

func (c *modelChecker) capAdd(service string) modelCheck {
	approved := c.exceptions.Services[service].CapAdd
	return c.listOf(func(path string, v any) error {
		capability, ok := v.(string)
		if !ok {
			return modelViolation(path, "must be a string")
		}
		if !slices.Contains(exemptibleCapabilities, capability) {
			return modelViolation(path, "capability %s cannot be approved", capability)
		}
		if !slices.Contains(approved, capability) {
			return modelViolation(path, "capability %s has no approved exception", capability)
		}
		return nil
	})
}

func (c *modelChecker) sysctls(service string) modelCheck {
	approved := c.exceptions.Services[service].Sysctls
	return c.mapByKey(func(key string) modelCheck {
		return func(path string, v any) error {
			value, ok := scalarString(v)
			if !ok {
				return modelViolation(path, "must be a scalar")
			}
			if !strings.HasPrefix(key, exemptibleSysctlPrefix) {
				return modelViolation(path, "only %s* sysctls can be approved", exemptibleSysctlPrefix)
			}
			if want, ok := approved[key]; !ok || want != value {
				return modelViolation(path, "sysctl %s=%s has no approved exception", key, value)
			}
			return nil
		}
	})
}

func (c *modelChecker) extraHosts(service string) modelCheck {
	approved := map[string]bool{}
	for _, entry := range c.exceptions.Services[service].ExtraHosts {
		approved[canonicalExtraHost(entry)] = true
	}
	return c.listOf(func(path string, v any) error {
		entry, ok := v.(string)
		if !ok {
			return modelViolation(path, "must be a string")
		}
		if !approved[canonicalExtraHost(entry)] {
			return modelViolation(path, "extra host %s has no approved exception", entry)
		}
		return nil
	})
}

// canonicalExtraHost renders "host:ip" and "host=ip" (the loader's output
// form) identically. The separator is the first "=" if any, else the first
// ":", so IPv6 addresses keep their colons.
func canonicalExtraHost(entry string) string {
	if host, ip, found := strings.Cut(entry, "="); found {
		return host + "=" + ip
	}
	host, ip, _ := strings.Cut(entry, ":")
	return host + "=" + ip
}

func (c *modelChecker) shmSize(service string) modelCheck {
	approved := c.exceptions.Services[service].ShmSize
	return func(path string, v any) error {
		got, ok := integerValue(v)
		if !ok {
			return modelViolation(path, "must be a byte size")
		}
		want, err := parseByteSize(approved)
		if approved == "" || err != nil || want != got {
			return modelViolation(path, "shm_size %d has no approved exception", got)
		}
		return nil
	}
}

func scalarString(v any) (string, bool) {
	switch s := v.(type) {
	case string:
		return s, true
	case json.Number:
		return s.String(), true
	case bool:
		return strconv.FormatBool(s), true
	}
	return "", false
}

// parseByteSize reads a size such as "67108864", "64m" or "1gb" (binary
// multiples, case-insensitive), the notation Compose accepts for shm_size.
func parseByteSize(text string) (int64, error) {
	text = strings.ToLower(strings.TrimSpace(text))
	digits := strings.TrimRightFunc(text, unicode.IsLetter)
	unit := strings.TrimPrefix(text, digits)
	multiplier, ok := map[string]int64{
		"": 1, "b": 1, "k": 1 << 10, "kb": 1 << 10, "m": 1 << 20, "mb": 1 << 20, "g": 1 << 30, "gb": 1 << 30,
	}[unit]
	if !ok {
		return 0, fmt.Errorf("unknown size unit %q", unit)
	}
	n, err := strconv.ParseInt(digits, 10, 64)
	if err != nil || n < 0 {
		return 0, fmt.Errorf("invalid size %q", text)
	}
	return n * multiplier, nil
}
