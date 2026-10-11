package backup

import (
	"archive/tar"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/klauspost/compress/zstd"
)

// Member is one file of an archive. Open yields its bytes and may be called
// more than once: the writer reads every member twice, to checksum it for the
// manifest and to store it.
type Member struct {
	Name string
	Open func() (io.ReadCloser, error)
}

// BytesMember is a member held in memory.
func BytesMember(name string, data []byte) Member {
	return Member{Name: name, Open: func() (io.ReadCloser, error) { return io.NopCloser(bytes.NewReader(data)), nil }}
}

// FileMember is a member read from a file that must not change while the
// archive is written.
func FileMember(name, path string) Member {
	return Member{Name: name, Open: func() (io.ReadCloser, error) { return os.Open(path) }} //nolint:gosec // path is the private snapshot this package made
}

// WriteArchive writes manifest.json followed by members, then finishes the
// stream. It fills m.SHA256 and sizes from the members themselves, so the
// manifest cannot disagree with what is stored; a member that changes between
// the two reads is an error.
func (w *Writer) WriteArchive(m Manifest, members []Member) error {
	if err := w.writeAll(m, members); err != nil {
		return errors.Join(err, w.Close())
	}
	return w.Close()
}

func (w *Writer) writeAll(m Manifest, members []Member) error {
	digests, err := digestAll(members)
	if err != nil {
		return err
	}
	m.SHA256 = make(map[string]string, len(members))
	for name, d := range digests {
		m.SHA256[name] = d.sum
	}
	encoded, err := EncodeManifest(m)
	if err != nil {
		return err
	}
	if err := w.add(m, ManifestName, int64(len(encoded)), bytes.NewReader(encoded)); err != nil {
		return err
	}
	for _, member := range members {
		if err := w.addMember(m, member, digests[member.Name]); err != nil {
			return err
		}
	}
	return nil
}

// Close ends the tar stream and the zstd frame. It does not close the
// underlying writer.
func (w *Writer) Close() error {
	return errors.Join(w.tw.Close(), w.zw.Close())
}

type digest struct {
	sum  string
	size int64
}

func digestAll(members []Member) (map[string]digest, error) {
	out := make(map[string]digest, len(members))
	for _, member := range members {
		if _, dup := out[member.Name]; dup || member.Name == ManifestName {
			return nil, fmt.Errorf("archive member %q listed twice or reserved", member.Name)
		}
		d, err := digestOf(member)
		if err != nil {
			return nil, err
		}
		out[member.Name] = d
	}
	return out, nil
}

func digestOf(member Member) (digest, error) {
	r, err := member.Open()
	if err != nil {
		return digest{}, fmt.Errorf("open %s: %w", member.Name, err)
	}
	defer r.Close()
	h := sha256.New()
	n, err := io.Copy(h, r)
	if err != nil {
		return digest{}, fmt.Errorf("read %s: %w", member.Name, err)
	}
	return digest{sum: hex.EncodeToString(h.Sum(nil)), size: n}, nil
}

func (w *Writer) addMember(m Manifest, member Member, want digest) error {
	r, err := member.Open()
	if err != nil {
		return fmt.Errorf("open %s: %w", member.Name, err)
	}
	defer r.Close()
	h := sha256.New()
	if err := w.add(m, member.Name, want.size, io.TeeReader(r, h)); err != nil {
		return err
	}
	if hex.EncodeToString(h.Sum(nil)) != want.sum {
		return fmt.Errorf("%s changed while the archive was written", member.Name)
	}
	return nil
}

func (w *Writer) add(m Manifest, name string, size int64, r io.Reader) error {
	header := &tar.Header{Typeflag: tar.TypeReg, Name: name, Mode: 0o600, Size: size, ModTime: m.CreatedAt}
	if err := w.tw.WriteHeader(header); err != nil {
		return fmt.Errorf("write header of %s: %w", name, err)
	}
	if _, err := io.Copy(w.tw, r); err != nil {
		return fmt.Errorf("write %s: %w", name, err)
	}
	return nil
}

// ReadManifest returns the manifest of an archive: its first member. It
// decompresses only as much as the manifest needs.
func ReadManifest(r io.Reader) (Manifest, error) {
	zr, err := zstd.NewReader(r,
		zstd.WithDecoderConcurrency(1),
		zstd.WithDecoderMaxWindow(maxWindowBytes),
		zstd.WithDecoderMaxMemory(maxWindowBytes))
	if err != nil {
		return Manifest{}, fmt.Errorf("open zstd stream: %w", err)
	}
	defer zr.Close()
	tr := tar.NewReader(zr)
	header, err := tr.Next()
	if err != nil {
		return Manifest{}, fmt.Errorf("read first archive member: %w", err)
	}
	if header.Name != ManifestName || header.Typeflag != tar.TypeReg || header.Size > maxManifestSize {
		return Manifest{}, fmt.Errorf("first archive member is %q, want a regular %s of at most %d bytes", header.Name, ManifestName, maxManifestSize)
	}
	data := make([]byte, header.Size)
	if _, err := io.ReadFull(tr, data); err != nil {
		return Manifest{}, fmt.Errorf("read %s: %w", ManifestName, err)
	}
	return ParseManifest(data)
}
