// Package backup creates control-plane archives and restores them offline
// (spec §29; ADR-0020). An archive is a zstd-compressed tar holding
// manifest.json, the SQLite snapshot, config/ and known_hosts; KEK files are
// never included. Restore stages and neutralizes a copy, then moves files into
// place under a write-ahead journal that every start of the daemon or of the
// restore command recovers before the database is opened.
//
// W0 contract: signatures are frozen; bodies landed in M2 tasks T5 and T6.
package backup

import (
	"archive/tar"
	"context"
	"io"
	"time"

	"github.com/klauspost/compress/zstd"

	"github.com/autarquico/supermgmt/internal/domain"
)

// Extension is the archive suffix fixed by §29.1.
const Extension = ".tar.zst"

// FormatVersion is the manifest format this binary writes and reads.
const FormatVersion = 1

// JournalName is the restore journal in the data directory (§29.2 phase B).
const JournalName = "restore.journal"

// Manifest is manifest.json.
type Manifest struct {
	FormatVersion    int               `json:"format_version"`
	SMVersion        string            `json:"sm_version"`
	SchemaVersion    int               `json:"schema_version"`
	CreatedAt        time.Time         `json:"created_at"`
	KEKIDs           []domain.ID       `json:"kek_ids"`
	ConfigGeneration int64             `json:"config_generation"`
	SHA256           map[string]string `json:"sha256"` // member path -> hex digest, every member but the manifest
}

// Writer writes one archive: tar members inside a zstd stream.
type Writer struct {
	zw *zstd.Encoder
	tw *tar.Writer
}

// NewWriter starts an archive on w. The caller writes to a 0600 temp file,
// fsyncs and renames it into place.
func NewWriter(w io.Writer) (*Writer, error) {
	zw, err := zstd.NewWriter(w)
	if err != nil {
		return nil, err
	}
	return &Writer{zw: zw, tw: tar.NewWriter(zw)}, nil
}

// RestoreOptions drives `sm backup restore --offline`.
type RestoreOptions struct {
	Archive string
	DataDir string
	KeysDir string
	DBPath  string
	Clock   domain.Clock
	IDs     domain.IDGenerator
}

// Restore runs phases A and B of §29.2. The caller holds the database lock.
// Phase A errors leave every live file untouched; a missing or failing KEK is
// exit 9 naming the ids.
func Restore(ctx context.Context, o RestoreOptions) error {
	return restore(ctx, o, env{})
}

// Recover finishes or discards an interrupted restore from dataDir's journal.
// The daemon and the restore command call it after taking the database lock
// and before opening the database.
func Recover(dataDir string) error {
	return recoverRestore(dataDir, env{})
}
