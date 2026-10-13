package manifest

import (
	"net/netip"
	"testing"
	"time"

	"github.com/autarquico/supermgmt/internal/health"
)

func manifestWith(rollback string, h *ManifestHealth) *Manifest {
	m := &Manifest{}
	if rollback != "" {
		m.Spec.Rollback = &Rollback{Mode: rollback}
	}
	m.Spec.Health = h
	return m
}

func TestEffective_RollbackPrecedence(t *testing.T) {
	tests := []struct {
		name     string
		cp       string
		stateful bool
		manifest *Manifest
		want     string
	}{
		{"no manifest keeps control plane automatic", "automatic", false, nil, "automatic"},
		{"no manifest keeps control plane manual", "manual", false, nil, "manual"},
		{"manifest manual downgrades automatic", "automatic", false, manifestWith("manual", nil), "manual"},
		{"manifest automatic never upgrades manual", "manual", false, manifestWith("automatic", nil), "manual"},
		{"manifest automatic keeps automatic", "automatic", false, manifestWith("automatic", nil), "automatic"},
		{"manifest silent keeps automatic", "automatic", false, manifestWith("", nil), "automatic"},
		{"stateful forces manual", "automatic", true, nil, "manual"},
		{"stateful ignores manifest automatic", "automatic", true, manifestWith("automatic", nil), "manual"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := Effective(DeploymentPolicy{Rollback: tt.cp, Stateful: tt.stateful}, tt.manifest)
			if err != nil {
				t.Fatal(err)
			}
			if got.Rollback != tt.want {
				t.Fatalf("rollback = %q, want %q", got.Rollback, tt.want)
			}
		})
	}
}

func TestEffective_RejectsUnknownControlPlaneRollback(t *testing.T) {
	for _, mode := range []string{"", "always"} {
		_, err := Effective(DeploymentPolicy{Rollback: mode}, nil)
		requireInvalid(t, mode, err)
	}
}

func TestEffective_ManifestHealthIsNodeScopeAndManifestOrigin(t *testing.T) {
	m := manifestWith("", &ManifestHealth{
		Type: "http", Port: 8080, Path: "/h",
		Timeout: 3 * time.Second, Interval: 5 * time.Second, Attempts: 12,
	})
	got, err := Effective(DeploymentPolicy{Rollback: "automatic"}, m)
	if err != nil {
		t.Fatal(err)
	}
	want := health.Check{
		Origin: health.OriginManifest, Type: "http", Scope: health.ScopeNode, Port: 8080,
		Path: "/h", Timeout: 3 * time.Second, Interval: 5 * time.Second, Attempts: 12,
	}
	if got.Health == nil || *got.Health != want {
		t.Fatalf("health = %+v, want %+v", got.Health, want)
	}
}

func TestEffective_ControlPlaneHealthWins(t *testing.T) {
	cp := &health.Check{
		Origin: health.OriginManifest /* wrong on purpose */, Type: "https",
		Scope: health.ScopeControlPlane, URL: "https://app.example/h", Attempts: 3,
	}
	m := manifestWith("", &ManifestHealth{Type: "tcp", Port: 1})
	got, err := Effective(DeploymentPolicy{Rollback: "manual", Health: cp}, m)
	if err != nil {
		t.Fatal(err)
	}
	if got.Health.Type != "https" || got.Health.Scope != health.ScopeControlPlane || got.Health.Origin != health.OriginControlPlane {
		t.Fatalf("control-plane health must win and carry its origin: %+v", got.Health)
	}
	if cp.Origin != health.OriginManifest {
		t.Fatal("input check was mutated")
	}
}

func TestEffective_NoHealthWhenNeitherSideDefinesOne(t *testing.T) {
	for _, m := range []*Manifest{nil, manifestWith("manual", nil)} {
		got, err := Effective(DeploymentPolicy{Rollback: "automatic"}, m)
		if err != nil {
			t.Fatal(err)
		}
		if got.Health != nil {
			t.Fatalf("health = %+v, want nil", got.Health)
		}
	}
}

func TestEffective_ControlPlaneOnlyFieldsPassThroughAndAreCopied(t *testing.T) {
	addr := netip.MustParseAddr("10.0.0.5")
	cp := DeploymentPolicy{
		Rollback:             "automatic",
		Stateful:             true,
		AllowedBindAddresses: []netip.Addr{addr},
		PreDeployBackup:      &Backup{Template: BackupPostgresV1, Args: map[string]string{"database": "app"}, Timeout: 10 * time.Minute},
	}
	got, err := Effective(cp, manifestWith("automatic", nil))
	if err != nil {
		t.Fatal(err)
	}
	if !got.Stateful || len(got.AllowedBindAddresses) != 1 || got.AllowedBindAddresses[0] != addr ||
		got.PreDeployBackup.Template != BackupPostgresV1 || got.PreDeployBackup.Timeout != 10*time.Minute {
		t.Fatalf("control-plane fields lost: %+v", got)
	}
	got.AllowedBindAddresses[0] = netip.MustParseAddr("10.9.9.9")
	got.PreDeployBackup.Args["database"] = "other"
	if cp.AllowedBindAddresses[0] != addr || cp.PreDeployBackup.Args["database"] != "app" {
		t.Fatal("Effective aliases its input")
	}
}
