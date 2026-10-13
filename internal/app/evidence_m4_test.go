package app

import (
	"bytes"
	"context"
	"testing"

	"github.com/autarquico/supermgmt/internal/deployments"
	"github.com/autarquico/supermgmt/internal/domain"
	"github.com/autarquico/supermgmt/internal/jobs"
)

// evidenceCrash is a deployment interrupted at its compose up, with the
// project's containers all up and stable.
func evidenceCrash(t *testing.T) (*reconcileWorld, jobs.Intent) {
	t.Helper()
	w := newReconcileWorld(t)
	dep := w.queued()
	job := w.crashAt("compose.up")
	w.projectIs(w.containersOf(w.planOf(dep.ID).Content, dep.ID))
	return w, w.intentOf(job.ID, deployments.StepDeploy)
}

func (w *reconcileWorld) collect(in jobs.Intent) (jobs.Evidence, error) {
	w.t.Helper()
	return w.router.Collect(context.Background(), in)
}

func TestDeploymentEvidence_ComposeUpIsProvenOnlyByADoneFileWithExitZero(t *testing.T) {
	for _, tt := range []struct {
		name        string
		marker      string
		wantProven  bool
		wantProof   string
		wantClass   jobs.Classification
		wantDoneBit bool
	}{
		{"never began", "absent", true, jobs.ProofMarkerAbsent, jobs.ClassNotStarted, true},
		{"killed while running", "started", false, "", jobs.ClassComplete, false},
		{"finished with a failure", "done 1", false, jobs.ProofDoneFile, jobs.ClassComplete, true},
		{"finished", "done 0", true, jobs.ProofDoneFile, jobs.ClassComplete, true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			w, up := evidenceCrash(t)
			w.markerIs(up, tt.marker)

			ev, err := w.collect(up)

			mustf(t, err, "Collect")
			if ev.Proven() != tt.wantProven || ev.Proof != tt.wantProof || ev.Classification != tt.wantClass || ev.Done != tt.wantDoneBit {
				t.Errorf("evidence %+v; want proven=%v proof=%q class=%q done=%v", ev, tt.wantProven, tt.wantProof, tt.wantClass, tt.wantDoneBit)
			}
			if len(ev.Fingerprint) == 0 {
				t.Error("evidence without a fingerprint would pair with any other empty sample")
			}
		})
	}
}

func TestDeploymentEvidence_TwoSamplesOfAStableProjectHaveTheSameFingerprint(t *testing.T) {
	w, up := evidenceCrash(t)
	w.markerIs(up, "done 0")

	first, err := w.collect(up)
	mustf(t, err, "first Collect")
	second, err := w.collect(up)
	mustf(t, err, "second Collect")

	if !bytes.Equal(first.Fingerprint, second.Fingerprint) {
		t.Errorf("fingerprints differ: %s vs %s", first.Fingerprint, second.Fingerprint)
	}
}

func TestDeploymentEvidence_AProjectStillChangingIsNoEvidenceYet(t *testing.T) {
	w, up := evidenceCrash(t)
	w.markerIs(up, "done 0")
	dep := domain.ID(up.TargetID)
	containers := w.containersOf(w.planOf(dep).Content, dep)
	containers[0].State.Status = "restarting"
	w.projectIs(containers)

	if _, err := w.collect(up); err == nil {
		t.Fatal("a restarting container was classified")
	}
}

func TestDeploymentEvidence_PullAndMaterializeAreCompleteOnceTheirDoneFileSaysExitZero(t *testing.T) {
	w, up := evidenceCrash(t)
	for _, step := range []string{deployments.StepPull, deployments.StepMaterialize} {
		in := w.intentOf(up.JobID, step)
		w.markerIs(in, "done 0")

		ev, err := w.collect(in)

		mustf(t, err, "Collect %s", step)
		if !ev.Proven() || ev.Classification != jobs.ClassComplete {
			t.Errorf("%s evidence %+v, want proven and complete", step, ev)
		}
	}
}

func TestDeploymentEvidence_AnUnknownMarkersDirectoryIsNoEvidence(t *testing.T) {
	w, up := evidenceCrash(t)
	w.markerIs(up, "unavailable")

	if _, err := w.collect(up); err == nil {
		t.Fatal("an unreadable markers directory was read as evidence")
	}
}

func TestDeploymentEvidence_AnOperationItDoesNotKnowIsNoEvidence(t *testing.T) {
	w, up := evidenceCrash(t)
	up.Operation = "compose.down"
	w.markerIs(up, "done 0")

	if _, err := w.collect(up); err == nil {
		t.Fatal("an operation no step dispatches was given evidence")
	}
}

func TestNewDeploymentEvidence_NeedsTheJobStore(t *testing.T) {
	f := newFixture(t)
	if _, err := NewDeploymentEvidence(f.cfg, Connector{}, nil); err == nil {
		t.Fatal("evidence without the job store was accepted")
	}
}

func TestEvidenceRouter_DeploymentIntentsNeedADeploymentSource(t *testing.T) {
	w, up := evidenceCrash(t)
	bare, err := NewEvidenceRouter(w.cfg, Connector{}, nil)
	mustf(t, err, "NewEvidenceRouter")

	if _, err := bare.Collect(context.Background(), up); err == nil {
		t.Fatal("a router without a deployment source answered for a deployment intent")
	}
}
