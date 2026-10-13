package compose

// labelResources injects the ownership labels of spec §20.3 step 9 into every
// service, volume and network of the tree, in place. The implicit default
// network is declared so that it carries them too.
func labelResources(root *node, t Target) {
	services := root.get("services")
	for _, e := range services.entries {
		addOwnershipLabels(e.val, t)
	}
	if anyServiceUsesDefaultNetwork(services) {
		labelDeclare(root, "networks", "default")
	}
	for _, section := range []string{"volumes", "networks"} {
		resources := root.get(section)
		if resources == nil {
			continue
		}
		for i := range resources.entries {
			resources.entries[i].val = labelMapping(resources.entries[i].val)
			addOwnershipLabels(resources.entries[i].val, t)
		}
	}
}

func addOwnershipLabels(resource *node, t Target) {
	labels := resource.get("labels")
	if labels == nil || labels.kind != mappingNode {
		labels = &node{kind: mappingNode}
		labelPut(resource, "labels", labels)
	}
	labelPut(labels, LabelOwner, labelString(string(t.Owner)))
	labelPut(labels, LabelProject, labelString(t.Project))
}

func anyServiceUsesDefaultNetwork(services *node) bool {
	for _, e := range services.entries {
		networks := e.val.get("networks")
		if networks == nil || networks.kind != mappingNode || networks.get("default") != nil {
			return true
		}
	}
	return false
}

func labelDeclare(root *node, section, name string) {
	resources := root.get(section)
	if resources == nil || resources.kind != mappingNode {
		resources = &node{kind: mappingNode}
		labelPut(root, section, resources)
	}
	if resources.get(name) == nil {
		labelPut(resources, name, &node{kind: mappingNode})
	}
}

func labelMapping(n *node) *node {
	if n.kind == mappingNode {
		return n
	}
	return &node{kind: mappingNode}
}

func labelString(value string) *node {
	return &node{kind: scalarNode, tag: "!!str", value: value}
}

// labelPut sets key in the mapping, replacing an existing entry.
func labelPut(mapping *node, key string, val *node) {
	for i := range mapping.entries {
		if mapping.entries[i].key == key {
			mapping.entries[i].val = val
			return
		}
	}
	mapping.entries = append(mapping.entries, entry{key: key, val: val})
}
