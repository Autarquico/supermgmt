package backup_test

import (
	"archive/tar"
	"bytes"
	"strings"
	"testing"

	"github.com/autarquico/supermgmt/internal/backup"
	"github.com/autarquico/supermgmt/internal/domain"
)

// archiveClaimingWindow is a valid archive whose zstd frame header declares a
// window of 1<<windowLog bytes, as a hostile one could.
func archiveClaimingWindow(t *testing.T, windowLog int) *bytes.Reader {
	t.Helper()
	manifest, err := backup.EncodeManifest(backup.Manifest{
		FormatVersion: backup.FormatVersion, SMVersion: "1", SchemaVersion: 3, CreatedAt: epoch,
		KEKIDs: []domain.ID{}, ConfigGeneration: 1,
		SHA256: map[string]string{backup.DatabaseName: strings.Repeat("a", 64)},
	})
	if err != nil {
		t.Fatal(err)
	}
	var tarball bytes.Buffer
	tw := tar.NewWriter(&tarball)
	_ = tw.WriteHeader(&tar.Header{Name: backup.ManifestName, Mode: 0o600, Size: int64(len(manifest)), Typeflag: tar.TypeReg})
	_, _ = tw.Write(manifest)
	_ = tw.Close()

	// One raw, last block in a frame without a content size: the window
	// descriptor (exponent, zero mantissa) is the byte after the header.
	block := uint32(tarball.Len())<<3 | 1
	frame := []byte{0x28, 0xB5, 0x2F, 0xFD, 0x00, byte(windowLog-10) << 3, byte(block), byte(block >> 8), byte(block >> 16)}
	return bytes.NewReader(append(frame, tarball.Bytes()...))
}

func TestReadManifestRefusesAnOversizedDecoderWindow(t *testing.T) {
	if _, err := backup.ReadManifest(archiveClaimingWindow(t, 20)); err != nil {
		t.Fatalf("ReadManifest with a small window: %v", err)
	}

	if _, err := backup.ReadManifest(archiveClaimingWindow(t, 28)); err == nil {
		t.Fatal("ReadManifest accepted a 256 MiB decoder window, beyond restore's cap")
	}
}
