package transport

import (
	"archive/tar"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"path"
	"slices"
	"strings"
)

const (
	// ManifestMaxEntries bounds the archive a manifest can verify: each entry
	// costs 32 bytes of memory, so a volume with more entries is refused, not
	// approximated.
	ManifestMaxEntries = 1 << 20
	// ManifestDetailLimit is the most entries a Manifest lists; above it only
	// the digest and counts remain.
	ManifestDetailLimit = 4096

	tarTrailer = 2 * 512
)

// ManifestEntry is what a volume copy must preserve of one archive member.
// Times are left out on purpose: an import does not promise them.
type ManifestEntry struct {
	Path     string `json:"path"`
	Type     string `json:"type"`
	Mode     int64  `json:"mode"`
	UID      int    `json:"uid"`
	GID      int    `json:"gid"`
	Size     int64  `json:"size"`
	Link     string `json:"link,omitempty"`
	DevMajor int64  `json:"dev_major,omitempty"`
	DevMinor int64  `json:"dev_minor,omitempty"`
	SHA256   string `json:"sha256,omitempty"`
}

// Manifest summarises a tar archive independently of member order. Equal
// digests mean equal paths, types, modes, numeric owners, sizes, link targets
// and file contents.
type Manifest struct {
	Digest  string
	Count   int
	Bytes   int64
	Entries []ManifestEntry // sorted by path; nil above ManifestDetailLimit
}

// TarManifest reads a whole tar archive from r. It fails closed: an archive
// that is empty, truncated, lacks its end-of-archive blocks, has bytes after
// them, holds a member it does not know or a path escaping the root is an
// error, never a smaller manifest.
func TarManifest(r io.Reader) (Manifest, error) {
	tail := &trailerReader{r: r}
	tr := tar.NewReader(tail)
	var leaves [][sha256.Size]byte
	var details []ManifestEntry
	var bytesTotal int64
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return Manifest{}, fmt.Errorf("tar manifest: %w", err)
		}
		if len(leaves) >= ManifestMaxEntries {
			return Manifest{}, fmt.Errorf("tar manifest: more than %d entries", ManifestMaxEntries)
		}
		entry, err := entryOf(hdr, tr)
		if err != nil {
			return Manifest{}, fmt.Errorf("tar manifest: %w", err)
		}
		line, err := json.Marshal(entry)
		if err != nil {
			return Manifest{}, fmt.Errorf("tar manifest: %w", err)
		}
		leaves = append(leaves, sha256.Sum256(line))
		bytesTotal += entry.Size
		if len(leaves) <= ManifestDetailLimit {
			details = append(details, entry)
		}
	}
	if err := tail.verifyEnd(); err != nil {
		return Manifest{}, fmt.Errorf("tar manifest: %w", err)
	}

	slices.SortFunc(leaves, func(a, b [sha256.Size]byte) int { return bytes.Compare(a[:], b[:]) })
	digest := sha256.New()
	for _, leaf := range leaves {
		digest.Write(leaf[:])
	}
	m := Manifest{Digest: hex.EncodeToString(digest.Sum(nil)), Count: len(leaves), Bytes: bytesTotal}
	if len(leaves) <= ManifestDetailLimit {
		slices.SortFunc(details, func(a, b ManifestEntry) int { return strings.Compare(a.Path, b.Path) })
		m.Entries = details
	}
	return m, nil
}

func entryOf(hdr *tar.Header, body io.Reader) (ManifestEntry, error) {
	name, err := cleanMember(hdr.Name)
	if err != nil {
		return ManifestEntry{}, err
	}
	e := ManifestEntry{Path: name, Mode: hdr.Mode & 0o7777, UID: hdr.Uid, GID: hdr.Gid}
	switch hdr.Typeflag {
	case tar.TypeReg:
		e.Type = "file"
		sum := sha256.New()
		n, err := io.Copy(sum, body)
		if err != nil {
			return ManifestEntry{}, fmt.Errorf("%s: %w", name, err)
		}
		e.Size, e.SHA256 = n, hex.EncodeToString(sum.Sum(nil))
	case tar.TypeDir:
		e.Type = "dir"
	case tar.TypeSymlink:
		e.Type, e.Link = "symlink", hdr.Linkname
	case tar.TypeLink:
		link, err := cleanMember(hdr.Linkname)
		if err != nil {
			return ManifestEntry{}, fmt.Errorf("%s: hard link %w", name, err)
		}
		e.Type, e.Link = "hardlink", link
	case tar.TypeChar, tar.TypeBlock:
		e.Type, e.DevMajor, e.DevMinor = map[byte]string{tar.TypeChar: "char", tar.TypeBlock: "block"}[hdr.Typeflag], hdr.Devmajor, hdr.Devminor
	case tar.TypeFifo:
		e.Type = "fifo"
	default:
		return ManifestEntry{}, fmt.Errorf("%s: unsupported member type %q", name, hdr.Typeflag)
	}
	if hdr.Typeflag != tar.TypeReg && hdr.Size != 0 {
		return ManifestEntry{}, fmt.Errorf("%s: a %s with a body", name, e.Type)
	}
	return e, nil
}

// cleanMember makes a member name comparable between two exports: no leading
// "./" or "/", no trailing "/", and nothing that climbs out of the root.
func cleanMember(name string) (string, error) {
	cleaned := path.Clean("/" + name)
	if name == "" || strings.ContainsRune(name, 0) || slices.Contains(strings.Split(name, "/"), "..") {
		return "", fmt.Errorf("member name %q is not valid", name)
	}
	return strings.TrimPrefix(cleaned, "/"), nil
}

// trailerReader remembers how much it passed and the last tarTrailer bytes, so
// the end of the archive can be checked: archive/tar reports a clean EOF for an
// empty input and for a missing trailer alike.
type trailerReader struct {
	r     io.Reader
	total int64
	last  []byte
}

func (t *trailerReader) Read(p []byte) (int, error) {
	n, err := t.r.Read(p)
	t.total += int64(n)
	t.last = append(t.last, p[:n]...)
	if len(t.last) > tarTrailer {
		t.last = append(t.last[:0], t.last[len(t.last)-tarTrailer:]...)
	}
	return n, err
}

// verifyEnd drains what archive/tar left unread and requires the archive to be
// whole blocks ending in two zero blocks, with nothing but zeros after the
// first end-of-archive block.
func (t *trailerReader) verifyEnd() error {
	rest := &zeroSink{}
	if _, err := io.Copy(rest, t); err != nil {
		return err
	}
	if rest.dirty {
		return errors.New("the archive has data after its end-of-archive blocks")
	}
	if t.total == 0 || t.total%512 != 0 || len(t.last) < tarTrailer || !allZero(t.last) {
		return errors.New("the archive is truncated or lacks its end-of-archive blocks")
	}
	return nil
}

// zeroSink notes whether any byte written to it is not zero.
type zeroSink struct{ dirty bool }

func (z *zeroSink) Write(p []byte) (int, error) {
	z.dirty = z.dirty || !allZero(p)
	return len(p), nil
}

func allZero(b []byte) bool {
	for _, c := range b {
		if c != 0 {
			return false
		}
	}
	return true
}
