package daemon

import (
	"context"
	"fmt"

	"github.com/autarquico/supermgmt/internal/api/wire"
	"github.com/autarquico/supermgmt/internal/database"
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

func (b *builder) checkKeys() wire.DoctorCheck {
	active, _ := b.kit.keys.Active()
	if active == "" {
		return wire.DoctorCheck{Name: "keys", Status: checkFail, Detail: "no active master key is loaded"}
	}
	return wire.DoctorCheck{Name: "keys", Status: checkOK, Detail: "active master key " + active.String()}
}
