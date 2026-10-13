package compose

// pruneUnusedResources removes from the expected model the top-level networks
// and volumes no service references, and the section itself once it is empty.
// Compose v5.5.1's `config` omits them (fixture evidence: T17a, unused-resource
// case), so the loader's model, which keeps every declaration, would otherwise
// never match the node. The implicit "default" network is never pruned.
func pruneUnusedResources(model map[string]any) {
	services, _ := model["services"].(map[string]any)
	pruneUnused(model, "networks", usedNetworks(services))
	pruneUnused(model, "volumes", usedVolumes(services))
}

func pruneUnused(model map[string]any, section string, used map[string]bool) {
	declared, ok := model[section].(map[string]any)
	if !ok {
		return
	}
	for name := range declared {
		if !used[name] && (section != "networks" || name != "default") {
			delete(declared, name)
		}
	}
	if len(declared) == 0 {
		delete(model, section)
	}
}

func usedNetworks(services map[string]any) map[string]bool {
	used := map[string]bool{}
	for _, s := range services {
		service, _ := s.(map[string]any)
		switch networks := service["networks"].(type) {
		case map[string]any:
			for name := range networks {
				used[name] = true
			}
		case []any:
			for _, n := range networks {
				if name, ok := n.(string); ok {
					used[name] = true
				}
			}
		}
	}
	return used
}

func usedVolumes(services map[string]any) map[string]bool {
	used := map[string]bool{}
	for _, s := range services {
		service, _ := s.(map[string]any)
		mounts, _ := service["volumes"].([]any)
		for _, m := range mounts {
			mount, _ := m.(map[string]any)
			if mount["type"] != "volume" {
				continue
			}
			if source, ok := mount["source"].(string); ok {
				used[source] = true
			}
		}
	}
	return used
}
