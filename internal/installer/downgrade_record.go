package installer

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"path/filepath"
	"time"

	"github.com/google/uuid"
)

// pendingAuditDir holds audit records the installer wrote while the daemon was
// stopped. The next daemon start imports and deletes them (ADR-0035).
const pendingAuditDir = "audit-pending"

const actionDowngradeAuthorized = "instance.downgrade_authorized"

// downgradeRecord is the JSON the daemon decodes strictly (internal/app
// PendingAudit): the field set must match exactly.
type downgradeRecord struct {
	EventID  string    `json:"event_id"`
	Action   string    `json:"action"`
	OSUID    int       `json:"os_uid"`
	OSUser   string    `json:"os_user"`
	SudoUser string    `json:"sudo_user"`
	From     string    `json:"from"`
	To       string    `json:"to"`
	At       time.Time `json:"at"`
}

// recordDowngrade makes an --allow-downgrade authorization durable before the
// swap, since upgrade.json is deleted at the end. A resumed swap derives the
// same event id, so it never writes a second record for the same upgrade.
func (u *upgrader) recordDowngrade() error {
	if !u.st.AllowDowngrade {
		return nil
	}
	files, dataDir := u.d.Files, u.t.l.DataDir
	id := downgradeEventID(u.st)
	path := filepath.Join(dataDir, pendingAuditDir, id+".json")
	if files.Exists(path) {
		return nil
	}
	data, err := json.Marshal(downgradeRecord{
		EventID: id, Action: actionDowngradeAuthorized,
		OSUID: u.d.Host.UID, OSUser: u.d.Host.Env["USER"], SudoUser: u.d.Host.Env["SUDO_USER"],
		From: u.st.FromVersion, To: u.st.ToVersion, At: u.d.Clock.Now().UTC(),
	})
	if err != nil {
		return fmt.Errorf("render the downgrade record: %w", err)
	}
	owner := u.pendingAuditOwner()
	dir := filepath.Dir(path)
	if err := files.MkdirAll(dir, 0o700, owner); err != nil {
		return fmt.Errorf("create %s: %w", dir, err)
	}
	if err := files.WriteFile(path, append(data, '\n'), 0o600, owner); err != nil {
		return fmt.Errorf("write the downgrade record: %w", err)
	}
	for _, d := range []string{dir, dataDir} {
		if err := files.SyncDir(d); err != nil {
			return fmt.Errorf("sync %s: %w", d, err)
		}
	}
	return nil
}

// pendingAuditOwner lets the service account, which imports and deletes the
// record, read it; a local install runs as the caller.
func (u *upgrader) pendingAuditOwner() Owner {
	if u.t.runAs == "" {
		return Owner{}
	}
	return Owner{User: u.t.runAs, Group: u.t.runAs}
}

// downgradeEventID derives a UUIDv7-shaped id from the upgrade's identity, so
// the id survives a crash between writing the record and swapping.
func downgradeEventID(st upgradeState) string {
	sum := sha256.Sum256(fmt.Appendf(nil, "%s|%s|%d", st.OldSHA256, st.NewSHA256, st.UpdatedAt.UnixNano()))
	var id uuid.UUID
	copy(id[:], sum[:])
	id[6] = id[6]&0x0f | 0x70
	id[8] = id[8]&0x3f | 0x80
	return id.String()
}
