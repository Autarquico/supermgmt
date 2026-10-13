package compose

import "testing"

const labelDocument = `
services:
  web:
    image: x
    labels:
      team: core
  worker:
    image: y
    networks:
      backend:
volumes:
  data:
  cache: {labels: {tier: hot}}
networks:
  backend:
    internal: true
`

func labelTree(t *testing.T) *node {
	t.Helper()
	root, err := parseMerged([]byte(labelDocument))
	if err != nil {
		t.Fatal(err)
	}
	labelResources(root, Target{Project: "sm-app-prod", Owner: "tgt_1"})
	return root
}

func labelsOf(t *testing.T, resource *node) map[string]string {
	t.Helper()
	out := map[string]string{}
	labels := resource.get("labels")
	if labels == nil {
		t.Fatal("resource has no labels")
	}
	for _, e := range labels.entries {
		out[e.key] = e.val.value
	}
	return out
}

func TestLabelResources_EveryServiceVolumeAndNetworkIsLabeled(t *testing.T) {
	root := labelTree(t)
	resources := map[string]*node{
		"web":     root.get("services").get("web"),
		"worker":  root.get("services").get("worker"),
		"data":    root.get("volumes").get("data"),
		"cache":   root.get("volumes").get("cache"),
		"backend": root.get("networks").get("backend"),
		"default": root.get("networks").get("default"),
	}
	for name, resource := range resources {
		if resource == nil {
			t.Fatalf("%s is missing", name)
		}
		labels := labelsOf(t, resource)
		if labels[LabelOwner] != "tgt_1" || labels[LabelProject] != "sm-app-prod" {
			t.Errorf("%s labels = %v", name, labels)
		}
	}
}

func TestLabelResources_KeepsAuthorLabelsAndKeys(t *testing.T) {
	root := labelTree(t)
	if got := labelsOf(t, root.get("services").get("web"))["team"]; got != "core" {
		t.Errorf("author label lost: %q", got)
	}
	if got := labelsOf(t, root.get("volumes").get("cache"))["tier"]; got != "hot" {
		t.Errorf("volume label lost: %q", got)
	}
	if root.get("networks").get("backend").get("internal") == nil {
		t.Error("network key lost")
	}
}

func TestLabelResources_DefaultNetworkOnlyWhenUsed(t *testing.T) {
	root, err := parseMerged([]byte("services:\n  web:\n    image: x\n    networks:\n      backend:\nnetworks:\n  backend:\n"))
	if err != nil {
		t.Fatal(err)
	}
	labelResources(root, Target{Project: "p", Owner: "o"})
	if root.get("networks").get("default") != nil {
		t.Fatal("default network declared although no service attaches to it")
	}
}
