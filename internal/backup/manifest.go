package backup

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"slices"

	"github.com/autarquico/supermgmt/internal/domain"
)

// Members of an archive (spec §29.1). The manifest comes first so a reader can
// learn which KEKs an archive needs without decompressing the database.
const (
	ManifestName    = "manifest.json"
	DatabaseName    = "supermgmt.db"
	ConfigName      = "config/config.yaml"
	PolicyName      = "config/policies.yaml"
	KnownHostsName  = "known_hosts"
	maxManifestSize = 1 << 20
)

// EncodeManifest renders m as manifest.json.
func EncodeManifest(m Manifest) ([]byte, error) {
	if err := validateManifest(m); err != nil {
		return nil, err
	}
	return json.MarshalIndent(m, "", "  ")
}

// ParseManifest reads and validates manifest.json. Unknown fields, an unknown
// format version and malformed checksums are errors.
func ParseManifest(data []byte) (Manifest, error) {
	var m Manifest
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&m); err != nil {
		return Manifest{}, fmt.Errorf("decode manifest: %w", err)
	}
	if err := validateManifest(m); err != nil {
		return Manifest{}, err
	}
	return m, nil
}

func validateManifest(m Manifest) error {
	switch {
	case m.FormatVersion != FormatVersion:
		return fmt.Errorf("manifest format version %d is not supported (this binary reads %d)", m.FormatVersion, FormatVersion)
	case m.SchemaVersion < 1:
		return fmt.Errorf("manifest schema version %d is invalid", m.SchemaVersion)
	case m.CreatedAt.IsZero():
		return errors.New("manifest has no created_at")
	case m.ConfigGeneration < 1:
		return fmt.Errorf("manifest config generation %d is invalid", m.ConfigGeneration)
	}
	for _, id := range m.KEKIDs {
		if _, err := domain.ParseID(id.String()); err != nil {
			return fmt.Errorf("manifest kek id: %w", err)
		}
	}
	for name, sum := range m.SHA256 {
		raw, err := hex.DecodeString(sum)
		if err != nil || len(raw) != 32 {
			return fmt.Errorf("manifest checksum of %q is not a SHA-256 digest", name)
		}
		if name == ManifestName {
			return errors.New("manifest lists itself")
		}
	}
	if _, ok := m.SHA256[DatabaseName]; !ok {
		return fmt.Errorf("manifest has no checksum for %s", DatabaseName)
	}
	return nil
}

// sortedIDs returns ids sorted and without duplicates.
func sortedIDs(ids []domain.ID) []domain.ID {
	out := slices.Clone(ids)
	slices.Sort(out)
	return slices.Compact(out)
}
