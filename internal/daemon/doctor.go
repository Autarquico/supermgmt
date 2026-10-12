package daemon

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/autarquico/supermgmt/internal/api/wire"
	"github.com/autarquico/supermgmt/internal/app"
	"github.com/autarquico/supermgmt/internal/database"
	"github.com/autarquico/supermgmt/internal/domain"
	"github.com/autarquico/supermgmt/internal/providers/proxmox"
)

const (
	checkOK   = "ok"
	checkWarn = "warn"
	checkFail = "fail"
)

// doctor answers the read-only doctor route of the admin socket: what the
// daemon can tell about itself without touching a node.
func (b *builder) doctor(ctx context.Context) (wire.AdminDoctor, error) {
	report := wire.AdminDoctor{Mode: string(b.cfg.Instance.Mode)}
	report.Checks = append(report.Checks, b.checkDatabase(ctx))

	held, err := database.GetRestoreHold(ctx, b.db.Reader())
	report.RestoreHold = held || err != nil
	report.Checks = append(report.Checks, holdCheck(held, err))

	bound, err := b.adminBound(ctx)
	report.AdminBound = bound
	report.Checks = append(report.Checks, adminCheck(bound, err))

	report.Checks = append(report.Checks, b.checkKeys())
	report.Checks = append(report.Checks, b.checkProviders(ctx))
	return report, nil
}

func (b *builder) checkDatabase(ctx context.Context) wire.DoctorCheck {
	if _, err := database.GetInstance(ctx, b.db.Reader()); err != nil {
		return wire.DoctorCheck{Name: "database", Status: checkFail, Detail: err.Error()}
	}
	return wire.DoctorCheck{Name: "database", Status: checkOK}
}

func holdCheck(held bool, err error) wire.DoctorCheck {
	switch {
	case err != nil:
		return wire.DoctorCheck{Name: "restore_hold", Status: checkFail, Detail: "cannot be read: " + err.Error()}
	case held:
		return wire.DoctorCheck{Name: "restore_hold", Status: checkWarn, Detail: "in force: review the interrupted jobs, then run sm admin restore-complete"}
	}
	return wire.DoctorCheck{Name: "restore_hold", Status: checkOK}
}

func (b *builder) adminBound(ctx context.Context) (bool, error) {
	var exists bool
	err := b.db.Reader().QueryRowContext(ctx,
		`SELECT EXISTS (SELECT 1 FROM role_bindings b JOIN roles r ON r.id = b.role_id WHERE r.name = ?)`, adminRole).Scan(&exists)
	if err != nil {
		return false, fmt.Errorf("look for an admin binding: %w", err)
	}
	return exists, nil
}

func adminCheck(bound bool, err error) wire.DoctorCheck {
	switch {
	case err != nil:
		return wire.DoctorCheck{Name: "admin", Status: checkFail, Detail: err.Error()}
	case !bound:
		return wire.DoctorCheck{Name: "admin", Status: checkWarn, Detail: "no admin yet: run sm admin bootstrap-code"}
	}
	return wire.DoctorCheck{Name: "admin", Status: checkOK}
}

// staleSyncFactor is how many sync intervals may pass without a successful
// sync before the doctor calls a provider stale.
const staleSyncFactor = 3

// checkProviders reports the Proxmox providers' discovery: ok once each has
// synced recently, warn while the first sync is pending or when it is stale,
// fail when the last sync could not read the cluster. The installer waits for
// it as proof of the first discovery (ADR-0024).
func (b *builder) checkProviders(ctx context.Context) wire.DoctorCheck {
	providers, err := database.ListProviders(ctx, b.db.Reader())
	if err != nil {
		return wire.DoctorCheck{Name: "providers", Status: checkFail, Detail: err.Error()}
	}
	check := wire.DoctorCheck{Name: "providers", Status: checkOK}
	var details []string
	for _, p := range providers {
		if p.Type != proxmox.ProviderType || p.Status == app.ProviderStatusRemoved {
			continue
		}
		status, detail := b.providerHealth(ctx, p)
		check.Status = worse(check.Status, status)
		details = append(details, p.Name+": "+detail)
	}
	check.Detail = "no Proxmox provider is configured"
	if len(details) > 0 {
		check.Detail = strings.Join(details, "; ")
	}
	return check
}

func (b *builder) providerHealth(ctx context.Context, p domain.Provider) (status, detail string) {
	if p.Status == app.ProviderStatusError {
		report, _ := app.LatestSyncReport(ctx, b.db.Reader(), p.ID)
		return checkFail, "the last sync failed: " + report.Error
	}
	if p.LastSyncAt == nil {
		return checkWarn, "waiting for the first sync"
	}
	age := b.o.Clock.Now().Sub(*p.LastSyncAt)
	if age > staleSyncFactor*app.ProviderSyncInterval(p) {
		return checkWarn, fmt.Sprintf("last synced %s ago", age.Round(time.Second))
	}
	return checkOK, "synced " + p.LastSyncAt.UTC().Format(time.RFC3339)
}

func worse(a, b string) string {
	rank := map[string]int{checkOK: 0, checkWarn: 1, checkFail: 2}
	if rank[b] > rank[a] {
		return b
	}
	return a
}

func (b *builder) checkKeys() wire.DoctorCheck {
	active, _ := b.kit.keys.Active()
	if active == "" {
		return wire.DoctorCheck{Name: "keys", Status: checkFail, Detail: "no active master key is loaded"}
	}
	return wire.DoctorCheck{Name: "keys", Status: checkOK, Detail: "active master key " + active.String()}
}
