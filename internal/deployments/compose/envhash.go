package compose

import (
	"crypto/sha256"
	"encoding/hex"
	"sort"
	"strings"

	"go.yaml.in/yaml/v3"

	"github.com/autarquico/supermgmt/internal/audit"
)

// ExpectedEnvHashes computes, in memory, the set the node's compose.verify
// must report (spec §20.3 step 10, ADR-0010): for every environment entry the
// materialized model resolves, the SHA-256 of the value Compose hands the
// container. Values never leave this process.
//
// Entries come from the public environment (already interpolated, with every
// `$` doubled, so the doubling is undone exactly as the node program does) and
// from the bound secrets. Compose lets `environment:` win over `env_file`, so a
// name set in both is hashed from the environment; Materialize refuses that
// case before it can happen. A secret without a resolved value is omitted: the
// node then reports a name nobody expected, which is a mismatch.
//
// vars is the plan's variable map. Variables were substituted into the public
// model at freeze time, so nothing is read from it here.
func ExpectedEnvHashes(f Frozen, values []ResolvedSecret, _ map[string]string) []EnvHash {
	resolved := envhashPublicEnvironment(f.Public)
	byKey := make(map[materializeKey]audit.Secret, len(values))
	for _, v := range values {
		byKey[materializeKey{v.Ref, v.Version}] = v.Value
	}
	for _, u := range f.Secrets {
		value, ok := byKey[materializeKey{u.Ref, u.Version}]
		if !ok {
			continue
		}
		if resolved[u.Service] == nil {
			resolved[u.Service] = map[string]string{}
		}
		if _, set := resolved[u.Service][u.EnvName]; !set {
			resolved[u.Service][u.EnvName] = value.Reveal()
		}
	}
	return envhashSet(resolved)
}

func envhashSet(resolved map[string]map[string]string) []EnvHash {
	var set []EnvHash
	for service, env := range resolved {
		for name, value := range env {
			sum := sha256.Sum256([]byte(value))
			set = append(set, EnvHash{Service: service, EnvName: name, SHA256: hex.EncodeToString(sum[:])})
		}
	}
	sort.Slice(set, func(i, j int) bool {
		if set[i].Service != set[j].Service {
			return set[i].Service < set[j].Service
		}
		return set[i].EnvName < set[j].EnvName
	})
	return set
}

// envhashPublicEnvironment returns service -> name -> resolved value for the
// environment entries of the public model. Name-only entries (null) resolve
// to nothing under `env -i` and are left out.
func envhashPublicEnvironment(public []byte) map[string]map[string]string {
	resolved := map[string]map[string]string{}
	_, services, err := materializeParse(public)
	if err != nil {
		return resolved
	}
	for i := 0; i+1 < len(services.Content); i += 2 {
		env := materializeMapValue(services.Content[i+1], "environment")
		if env == nil || env.Kind != yaml.MappingNode {
			continue
		}
		entries := map[string]string{}
		for j := 0; j+1 < len(env.Content); j += 2 {
			if value := env.Content[j+1]; value.Kind == yaml.ScalarNode && value.Tag != "!!null" {
				entries[env.Content[j].Value] = strings.ReplaceAll(value.Value, "$$", "$")
			}
		}
		if len(entries) > 0 {
			resolved[services.Content[i].Value] = entries
		}
	}
	return resolved
}
