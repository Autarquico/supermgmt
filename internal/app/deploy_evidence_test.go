package app

import (
	"errors"
	"slices"
	"testing"

	"github.com/autarquico/supermgmt/internal/deployments/compose"
	"github.com/autarquico/supermgmt/internal/domain"
	"github.com/autarquico/supermgmt/internal/jobs"
)

const (
	evidenceDirectory = domain.ID("dir-new")
	evidenceWebImage  = "ghcr.io/acme/web@sha256:aaaa"
	evidenceJobsImage = "ghcr.io/acme/jobs@sha256:bbbb"
)

func evidenceContainer(service, id, image string, directory domain.ID, status string, exit int) upContainer {
	var c upContainer
	c.ID, c.Config.Image, c.State.Status, c.State.ExitCode = id, image, status, exit
	c.Config.Labels = map[string]string{composeServiceLabel: service, compose.LabelDeployment: directory.String()}
	return c
}

func evidenceWant() upExpectation {
	return upExpectation{directory: evidenceDirectory, images: map[string]string{"web": evidenceWebImage, "jobs": evidenceJobsImage}}
}

func TestClassifyUpContainers(t *testing.T) {
	web := evidenceContainer("web", "c1", evidenceWebImage, evidenceDirectory, "running", 0)
	worker := evidenceContainer("jobs", "c2", evidenceJobsImage, evidenceDirectory, "running", 0)
	tests := []struct {
		name       string
		containers []upContainer
		want       jobs.Classification
		unsettled  bool
	}{
		{"no container at all", nil, jobs.ClassNotStarted, false},
		{
			"only the previous deployment's containers",
			[]upContainer{evidenceContainer("web", "old", evidenceWebImage, "dir-old", "running", 0)},
			jobs.ClassNotStarted, false,
		},
		{"every service runs the frozen digest", []upContainer{web, worker}, jobs.ClassComplete, false},
		{
			"a service that ran to a clean exit counts",
			[]upContainer{web, evidenceContainer("jobs", "c2", evidenceJobsImage, evidenceDirectory, "exited", 0)},
			jobs.ClassComplete, false,
		},
		{"a frozen service is missing", []upContainer{web}, jobs.ClassPartialStable, false},
		{
			"one service still runs the previous container",
			[]upContainer{web, evidenceContainer("jobs", "old", evidenceJobsImage, "dir-old", "running", 0)},
			jobs.ClassPartialStable, false,
		},
		{
			"a container runs another digest",
			[]upContainer{web, evidenceContainer("jobs", "c2", "ghcr.io/acme/jobs@sha256:cccc", evidenceDirectory, "running", 0)},
			jobs.ClassPartialStable, false,
		},
		{
			"a service crashed",
			[]upContainer{web, evidenceContainer("jobs", "c2", evidenceJobsImage, evidenceDirectory, "exited", 1)},
			jobs.ClassPartialStable, false,
		},
		{
			"a leftover container joins the new ones",
			[]upContainer{web, worker, evidenceContainer("old", "x", "ghcr.io/acme/old@sha256:dddd", "dir-old", "running", 0)},
			jobs.ClassPartialStable, false,
		},
		{
			"a container is still being created",
			[]upContainer{web, evidenceContainer("jobs", "c2", evidenceJobsImage, evidenceDirectory, "created", 0)},
			"", true,
		},
		{"a container is restarting", []upContainer{evidenceContainer("web", "c1", evidenceWebImage, evidenceDirectory, "restarting", 0)}, "", true},
		{"a container is being removed", []upContainer{web, evidenceContainer("x", "c9", "i", "dir-old", "removing", 0)}, "", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := classifyUpContainers(tt.containers, evidenceWant())
			if tt.unsettled != errors.Is(err, errDeploymentContainersUnsettled) || (err != nil && !tt.unsettled) {
				t.Fatalf("error = %v, want unsettled=%v", err, tt.unsettled)
			}
			if got != tt.want {
				t.Errorf("classification = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestUpFingerprintIsOrderIndependentAndSeesEveryChange(t *testing.T) {
	a := evidenceContainer("web", "c1", evidenceWebImage, evidenceDirectory, "running", 0)
	b := evidenceContainer("jobs", "c2", evidenceJobsImage, evidenceDirectory, "running", 0)
	first := upFingerprint([]upContainer{a, b}, evidenceDirectory)
	if again := upFingerprint([]upContainer{b, a}, evidenceDirectory); !slices.Equal(first, again) {
		t.Errorf("the same containers in another order fingerprint differently: %v vs %v", first, again)
	}
	recreated := a
	recreated.ID = "c1-new"
	if moved := upFingerprint([]upContainer{recreated, b}, evidenceDirectory); slices.Equal(first, moved) {
		t.Error("a recreated container must change the fingerprint")
	}
	stopped := b
	stopped.State.Status = "exited"
	if moved := upFingerprint([]upContainer{a, stopped}, evidenceDirectory); slices.Equal(first, moved) {
		t.Error("a state change must change the fingerprint")
	}
}
