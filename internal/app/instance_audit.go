package app

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/autarquico/supermgmt/internal/database"
	"github.com/autarquico/supermgmt/internal/domain"
	smerr "github.com/autarquico/supermgmt/internal/errors"
)

const (
	// SettingBinaryVersion holds {"version","commit"} of the binary that last
	// started on this instance (ADR-0035).
	SettingBinaryVersion = "instance.binary_version"

	ActionVersionChanged      = "instance.version_changed"
	ActionDowngradeAuthorized = "instance.downgrade_authorized"

	// PendingAuditDir is the directory under the data directory where the
	// installer leaves downgrade authorizations for the next daemon start.
	PendingAuditDir = "audit-pending"

	// Directions of a version transition.
	DirectionUpgrade   = "upgrade"
	DirectionDowngrade = "downgrade"
	DirectionSame      = "same"    // same version, different commit
	DirectionUnknown   = "unknown" // a version that is not vMAJOR.MINOR.PATCH

	versionAuditSource  = "daemon_start"
	pendingAuditSource  = "installer_pending"
	pendingAuditMaxSize = 64 << 10
)

// PendingAudit is the record an --allow-downgrade upgrade writes before the
// swap, at <data dir>/audit-pending/<event_id>.json (mode 0600).
type PendingAudit struct {
	EventID  domain.ID `json:"event_id"`
	Action   string    `json:"action"`
	OSUID    int       `json:"os_uid"`
	OSUser   string    `json:"os_user"`
	SudoUser string    `json:"sudo_user"`
	From     string    `json:"from"`
	To       string    `json:"to"`
	At       time.Time `json:"at"`
}

// DecodePendingAudit parses and validates one record. Unknown fields are an
// error: a record written by a newer installer is kept, not half-imported.
func DecodePendingAudit(data []byte) (PendingAudit, error) {
	var p PendingAudit
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&p); err != nil {
		return PendingAudit{}, fmt.Errorf("decode pending audit: %w", err)
	}
	if dec.More() {
		return PendingAudit{}, errors.New("decode pending audit: trailing data")
	}
	if _, err := domain.ParseID(string(p.EventID)); err != nil {
		return PendingAudit{}, fmt.Errorf("pending audit event_id: %w", err)
	}
	if p.Action != ActionDowngradeAuthorized {
		return PendingAudit{}, fmt.Errorf("pending audit action %q is not %q", p.Action, ActionDowngradeAuthorized)
	}
	if p.From == "" || p.To == "" || p.At.IsZero() {
		return PendingAudit{}, errors.New("pending audit needs from, to and at")
	}
	return p, nil
}

// InstanceAudit records what happened to the binary while the daemon was not
// running: a version change, and downgrades the installer authorized offline.
type InstanceAudit struct {
	DB      *database.DB
	Clock   domain.Clock
	IDs     domain.IDGenerator
	DataDir string
	Log     *slog.Logger
}

type binaryVersion struct {
	Version string `json:"version"`
	Commit  string `json:"commit"`
}

// Record runs at daemon start, before anything is served, for the binary
// identified by version and commit. It fails only when the database cannot be
// written; a malformed pending record is kept and logged.
func (a InstanceAudit) Record(ctx context.Context, version, commit string) error {
	if err := a.recordVersionTransition(ctx, binaryVersion{Version: version, Commit: commit}); err != nil {
		return fmt.Errorf("record the version transition: %w", err)
	}
	return a.importPendingDowngrades(ctx)
}

func (a InstanceAudit) recordVersionTransition(ctx context.Context, running binaryVersion) error {
	return a.DB.WithWriteTx(ctx, func(ctx context.Context, tx *database.Tx) error {
		previous, found, err := readBinaryVersion(ctx, tx)
		if err != nil {
			return err
		}
		if found && previous == running {
			return nil
		}
		raw, err := json.Marshal(running)
		if err != nil {
			return err
		}
		err = database.PutSetting(ctx, tx, database.Setting{Key: SettingBinaryVersion, Value: raw, UpdatedAt: a.Clock.Now()})
		if err != nil || !found {
			return err
		}
		return a.appendEvent(ctx, tx, domain.Event{
			Timestamp: a.Clock.Now(), Source: versionAuditSource, Action: ActionVersionChanged,
			Severity: domain.SeverityInfo,
			Data: map[string]any{
				"from": previous.Version, "to": running.Version,
				"direction": direction(previous, running),
			},
		})
	})
}

func readBinaryVersion(ctx context.Context, q database.Querier) (binaryVersion, bool, error) {
	s, err := database.GetSetting(ctx, q, SettingBinaryVersion)
	if smerr.CodeOf(err) == smerr.CodeNotFound {
		return binaryVersion{}, false, nil
	}
	if err != nil {
		return binaryVersion{}, false, err
	}
	var v binaryVersion
	if err := json.Unmarshal(s.Value, &v); err != nil {
		return binaryVersion{}, false, fmt.Errorf("decode %s: %w", SettingBinaryVersion, err)
	}
	return v, true, nil
}

// appendEvent stores an instance event authored by the system. A zero EventID
// gets a fresh one.
func (a InstanceAudit) appendEvent(ctx context.Context, tx *database.Tx, e domain.Event) error {
	instance, err := database.GetInstance(ctx, tx)
	if err != nil {
		return err
	}
	if e.EventID == "" {
		e.EventID = a.IDs.NewID()
	}
	e.ActorType, e.ResourceType, e.ResourceID = domain.ActorSystem, domain.ResourceInstance, instance.ID
	e.Result = domain.ResultSucceeded
	_, err = database.EventsIn(tx).AppendEvent(ctx, e)
	return err
}

func (a InstanceAudit) importPendingDowngrades(ctx context.Context) error {
	dir := filepath.Join(a.DataDir, PendingAuditDir)
	entries, err := os.ReadDir(dir)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("read %s: %w", dir, err)
	}
	for _, entry := range entries {
		if !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}
		if err := a.importPending(ctx, filepath.Join(dir, entry.Name())); err != nil {
			return err
		}
	}
	return nil
}

// importPending turns one record into an event and removes the file. event_id
// is UNIQUE, so a crash between the insert and the removal leaves a file whose
// event already exists: the next start finds the conflict and removes it.
func (a InstanceAudit) importPending(ctx context.Context, path string) error {
	record, err := readPendingAudit(path)
	if err != nil {
		a.Log.Warn("pending audit record kept: it is not valid", slog.String("path", path), slog.Any("error", err))
		return nil
	}
	err = a.DB.WithWriteTx(ctx, func(ctx context.Context, tx *database.Tx) error {
		err := a.appendEvent(ctx, tx, record.event())
		if smerr.CodeOf(err) == smerr.CodeConflict {
			return nil
		}
		return err
	})
	if err != nil {
		return fmt.Errorf("import pending audit %s: %w", record.EventID, err)
	}
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("remove imported pending audit: %w", err)
	}
	return nil
}

func readPendingAudit(path string) (PendingAudit, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return PendingAudit{}, err
	}
	if !info.Mode().IsRegular() {
		return PendingAudit{}, errors.New("not a regular file")
	}
	f, err := os.Open(path) //nolint:gosec // a file of the data directory that was just checked
	if err != nil {
		return PendingAudit{}, err
	}
	defer func() { _ = f.Close() }()
	data, err := io.ReadAll(io.LimitReader(f, pendingAuditMaxSize+1))
	if err != nil {
		return PendingAudit{}, err
	}
	if len(data) > pendingAuditMaxSize {
		return PendingAudit{}, errors.New("record is too large")
	}
	record, err := DecodePendingAudit(data)
	if err != nil {
		return PendingAudit{}, err
	}
	if filepath.Base(path) != string(record.EventID)+".json" {
		return PendingAudit{}, fmt.Errorf("file name does not match event_id %s", record.EventID)
	}
	return record, nil
}

func (p PendingAudit) event() domain.Event {
	return domain.Event{
		EventID: p.EventID, Timestamp: p.At, Source: pendingAuditSource, Action: p.Action,
		Severity: domain.SeverityWarning,
		Data: map[string]any{
			"from": p.From, "to": p.To, "os_uid": p.OSUID, "os_user": p.OSUser, "sudo_user": p.SudoUser,
			"authorized_at": p.At.UTC().Format(time.RFC3339),
		},
	}
}

func direction(from, to binaryVersion) string {
	if from.Version == to.Version {
		return DirectionSame
	}
	a, okA := parseSemver(from.Version)
	b, okB := parseSemver(to.Version)
	if !okA || !okB {
		return DirectionUnknown
	}
	switch a.compare(b) {
	case -1:
		return DirectionUpgrade
	case 1:
		return DirectionDowngrade
	}
	return DirectionSame
}

type semver struct {
	core [3]int
	pre  string
}

func parseSemver(s string) (semver, bool) {
	s, ok := strings.CutPrefix(s, "v")
	if !ok {
		return semver{}, false
	}
	s, _, _ = strings.Cut(s, "+")
	s, pre, _ := strings.Cut(s, "-")
	parts := strings.Split(s, ".")
	if len(parts) != 3 {
		return semver{}, false
	}
	v := semver{pre: pre}
	for i, part := range parts {
		n, err := strconv.Atoi(part)
		if err != nil || n < 0 {
			return semver{}, false
		}
		v.core[i] = n
	}
	return v, true
}

// compare orders versions as -1, 0 or 1; a release is above its own pre-releases.
func (v semver) compare(o semver) int {
	for i := range v.core {
		if v.core[i] != o.core[i] {
			if v.core[i] < o.core[i] {
				return -1
			}
			return 1
		}
	}
	switch {
	case v.pre == o.pre:
		return 0
	case v.pre == "":
		return 1
	case o.pre == "":
		return -1
	}
	return strings.Compare(v.pre, o.pre)
}
