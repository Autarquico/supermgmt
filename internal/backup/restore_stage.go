package backup

import (
	"archive/tar"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"slices"
	"strings"

	"github.com/klauspost/compress/zstd"
)

// allowedMembers are the only names an archive may carry (spec §29.1).
var allowedMembers = []string{ManifestName, DatabaseName, ConfigName, PolicyName, KnownHostsName}

const maxWindowBytes = 128 << 20

// staged is the verified content of an archive extracted into the staging directory.
type staged struct {
	manifest Manifest
	members  map[string]bool // member name -> extracted
}

// stagedPath is where a member lands inside the staging directory.
func stagedPath(staging, member string) string {
	return filepath.Join(staging, filepath.FromSlash(member))
}

// extract is phase A steps 1 and 2: validate the manifest, then extract only
// listed members, each checked against its size cap and checksum while it
// streams. Nothing outside staging is touched.
func (e env) extract(ctx context.Context, archive io.Reader, staging string, schemaMax int) (staged, error) {
	budget := &budgetReader{r: archive, left: e.limits.total + 1<<20}
	zr, err := zstd.NewReader(budget,
		zstd.WithDecoderConcurrency(1),
		zstd.WithDecoderMaxWindow(maxWindowBytes))
	if err != nil {
		return staged{}, fmt.Errorf("open archive: %w", err)
	}
	defer zr.Close()
	decompressed := &budgetReader{r: zr, left: e.limits.total + 1<<20, what: "decompressed archive"}
	tr := tar.NewReader(decompressed)

	manifest, err := readManifestMember(tr)
	if err != nil {
		return staged{}, err
	}
	if manifest.SchemaVersion > schemaMax {
		return staged{}, fmt.Errorf("archive schema version %d is newer than this binary supports (%d)", manifest.SchemaVersion, schemaMax)
	}
	if err := checkListed(manifest); err != nil {
		return staged{}, err
	}
	out := staged{manifest: manifest, members: map[string]bool{}}
	var total int64
	for {
		if err := ctx.Err(); err != nil {
			return staged{}, err
		}
		header, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return staged{}, fmt.Errorf("read archive: %w", err)
		}
		if err := checkHeader(header, manifest, out.members, e.limits); err != nil {
			return staged{}, err
		}
		if total += header.Size; total > e.limits.total {
			return staged{}, fmt.Errorf("archive members exceed %d bytes in total", e.limits.total)
		}
		if err := extractMember(tr, header, manifest, staging); err != nil {
			return staged{}, err
		}
		out.members[header.Name] = true
	}
	if _, err := io.Copy(io.Discard, decompressed); err != nil { // what follows the tar footer is bounded too
		return staged{}, fmt.Errorf("read archive trailer: %w", err)
	}
	for name := range manifest.SHA256 {
		if !out.members[name] {
			return staged{}, fmt.Errorf("archive has no member %q listed in the manifest", name)
		}
	}
	return out, nil
}

func readManifestMember(tr *tar.Reader) (Manifest, error) {
	header, err := tr.Next()
	if err != nil {
		return Manifest{}, fmt.Errorf("read first archive member: %w", err)
	}
	if header.Name != ManifestName || header.Typeflag != tar.TypeReg || header.Size < 0 || header.Size > maxManifestSize {
		return Manifest{}, fmt.Errorf("first archive member is %q, want a regular %s of at most %d bytes", header.Name, ManifestName, maxManifestSize)
	}
	data := make([]byte, header.Size)
	if _, err := io.ReadFull(tr, data); err != nil {
		return Manifest{}, fmt.Errorf("read %s: %w", ManifestName, err)
	}
	return ParseManifest(data)
}

func checkListed(m Manifest) error {
	for name := range m.SHA256 {
		if !slices.Contains(allowedMembers, name) {
			return fmt.Errorf("manifest lists unexpected member %q", name)
		}
	}
	return nil
}

// checkHeader refuses everything but a listed, new, regular member of
// acceptable name and size.
func checkHeader(h *tar.Header, m Manifest, seen map[string]bool, l limits) error {
	name := h.Name
	switch {
	case path.IsAbs(name) || strings.Contains(name, "\\") || strings.ContainsRune(name, 0) ||
		slices.Contains(strings.Split(name, "/"), ".."):
		return fmt.Errorf("archive member %q has an unsafe path", name)
	case h.Typeflag != tar.TypeReg || h.Linkname != "":
		return fmt.Errorf("archive member %q is not a regular file (type %q)", name, string(h.Typeflag))
	case name == ManifestName:
		return errors.New("archive lists manifest.json twice")
	case !slices.Contains(allowedMembers, name):
		return fmt.Errorf("archive member %q is not an archive member", name)
	case seen[name]:
		return fmt.Errorf("archive member %q appears twice", name)
	}
	if _, listed := m.SHA256[name]; !listed {
		return fmt.Errorf("archive member %q is not listed in the manifest", name)
	}
	if h.Size < 0 || h.Size > l.capOf(name) {
		return fmt.Errorf("archive member %q is %d bytes, over its %d byte limit", name, h.Size, l.capOf(name))
	}
	return nil
}

func extractMember(tr io.Reader, h *tar.Header, m Manifest, staging string) error {
	if !filepath.IsLocal(filepath.FromSlash(h.Name)) || strings.Contains(h.Name, "..") {
		return fmt.Errorf("archive member %q escapes the staging directory", h.Name)
	}
	target := stagedPath(staging, h.Name)
	if err := os.MkdirAll(filepath.Dir(target), 0o700); err != nil {
		return fmt.Errorf("create staging directory: %w", err)
	}
	f, err := os.OpenFile(target, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600) //nolint:gosec // target is a listed member name under the private staging directory
	if err != nil {
		return fmt.Errorf("stage %s: %w", h.Name, err)
	}
	sum := sha256.New()
	n, err := io.Copy(io.MultiWriter(f, sum), io.LimitReader(tr, h.Size))
	if err == nil {
		err = f.Sync()
	}
	if err = errors.Join(err, f.Close()); err != nil {
		return fmt.Errorf("stage %s: %w", h.Name, err)
	}
	if n != h.Size {
		return fmt.Errorf("archive member %q is truncated", h.Name)
	}
	if got := hex.EncodeToString(sum.Sum(nil)); got != m.SHA256[h.Name] {
		return fmt.Errorf("checksum of %q does not match the manifest", h.Name)
	}
	return nil
}

// budgetReader fails once more than left bytes were read, so a decompression
// bomb stops at a bound however the archive is shaped.
type budgetReader struct {
	r    io.Reader
	left int64
	what string
}

func (b *budgetReader) Read(p []byte) (int, error) {
	if b.left <= 0 {
		var probe [1]byte
		if n, err := b.r.Read(probe[:]); n > 0 {
			return 0, fmt.Errorf("%s exceeds the size budget", b.describe())
		} else if err != nil {
			return 0, err
		}
		return 0, nil
	}
	if int64(len(p)) > b.left {
		p = p[:b.left]
	}
	n, err := b.r.Read(p)
	b.left -= int64(n)
	return n, err
}

func (b *budgetReader) describe() string {
	if b.what == "" {
		return "archive"
	}
	return b.what
}
