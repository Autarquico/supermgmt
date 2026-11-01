package transport

import (
	"archive/tar"
	"bytes"
	"strings"
	"testing"
)

type member struct {
	hdr  tar.Header
	body string
}

func file(name, body string, mode int64, uid, gid int) member {
	return member{hdr: tar.Header{Typeflag: tar.TypeReg, Name: name, Mode: mode, Uid: uid, Gid: gid, Size: int64(len(body))}, body: body}
}

func dir(name string, mode int64, uid, gid int) member {
	return member{hdr: tar.Header{Typeflag: tar.TypeDir, Name: name, Mode: mode, Uid: uid, Gid: gid}}
}

func symlink(name, target string) member {
	return member{hdr: tar.Header{Typeflag: tar.TypeSymlink, Name: name, Linkname: target, Mode: 0o777}}
}

func archive(t *testing.T, members ...member) []byte {
	t.Helper()
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	for _, m := range members {
		if err := tw.WriteHeader(&m.hdr); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write([]byte(m.body)); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func manifestOf(t *testing.T, b []byte) Manifest {
	t.Helper()
	m, err := TarManifest(bytes.NewReader(b))
	if err != nil {
		t.Fatal(err)
	}
	return m
}

func TestManifestIsIndependentOfOrderAndOfPathSpelling(t *testing.T) {
	a := archive(t, dir("./", 0o755, 0, 0), file("./a.txt", "alpha", 0o600, 1000, 1000), symlink("./link", "a.txt"))
	b := archive(t, symlink("link", "a.txt"), file("a.txt", "alpha", 0o600, 1000, 1000), dir(".", 0o755, 0, 0))
	if da, db := manifestOf(t, a).Digest, manifestOf(t, b).Digest; da != db {
		t.Errorf("digests differ: %s %s", da, db)
	}
	if m := manifestOf(t, a); m.Count != 3 || m.Bytes != 5 || len(m.Entries) != 3 {
		t.Errorf("manifest = %+v", m)
	}
}

func TestManifestSeesEveryPreservedProperty(t *testing.T) {
	base := []member{dir("d/", 0o755, 0, 0), file("d/f", "content", 0o600, 1000, 1000), symlink("d/l", "f")}
	want := manifestOf(t, archive(t, base...)).Digest
	changes := map[string]func(m []member) []member{
		"content":       func(m []member) []member { m[1] = file("d/f", "contenT", 0o600, 1000, 1000); return m },
		"size":          func(m []member) []member { m[1] = file("d/f", "content+", 0o600, 1000, 1000); return m },
		"mode":          func(m []member) []member { m[1] = file("d/f", "content", 0o644, 1000, 1000); return m },
		"uid":           func(m []member) []member { m[1] = file("d/f", "content", 0o600, 1001, 1000); return m },
		"gid":           func(m []member) []member { m[1] = file("d/f", "content", 0o600, 1000, 1001); return m },
		"dir mode":      func(m []member) []member { m[0] = dir("d/", 0o700, 0, 0); return m },
		"dir owner":     func(m []member) []member { m[0] = dir("d/", 0o755, 5, 0); return m },
		"link target":   func(m []member) []member { m[2] = symlink("d/l", "g"); return m },
		"path":          func(m []member) []member { m[1] = file("d/g", "content", 0o600, 1000, 1000); return m },
		"type":          func(m []member) []member { m[2] = file("d/l", "", 0o777, 0, 0); return m },
		"missing entry": func(m []member) []member { return m[:2] },
		"extra entry":   func(m []member) []member { return append(m, file("d/x", "", 0o600, 0, 0)) },
	}
	for name, change := range changes {
		got := manifestOf(t, archive(t, change(append([]member(nil), base...))...)).Digest
		if got == want {
			t.Errorf("a change of %s left the digest unchanged", name)
		}
	}
}

func TestManifestIgnoresTimes(t *testing.T) {
	a := file("f", "x", 0o600, 0, 0)
	b := file("f", "x", 0o600, 0, 0)
	b.hdr.ModTime = b.hdr.ModTime.AddDate(1, 0, 0)
	if manifestOf(t, archive(t, a)).Digest != manifestOf(t, archive(t, b)).Digest {
		t.Error("modification times must not matter")
	}
}

func TestManifestHandlesLongNamesAndLargeFiles(t *testing.T) {
	long := strings.Repeat("d/", 150) + "file"
	big := strings.Repeat("0123456789abcdef", 1<<16) // 1 MiB
	m := manifestOf(t, archive(t, file(long, big, 0o644, 0, 0)))
	if m.Count != 1 || m.Bytes != int64(len(big)) || m.Entries[0].Path != long {
		t.Errorf("manifest = %+v", m)
	}
}

func TestManifestOfAnEmptyArchiveIsValidButNotAnEmptyInput(t *testing.T) {
	if m := manifestOf(t, archive(t)); m.Count != 0 || m.Digest == "" {
		t.Errorf("empty archive = %+v", m)
	}
	if _, err := TarManifest(bytes.NewReader(nil)); err == nil {
		t.Error("zero bytes are not an archive")
	}
}

func TestManifestFailsClosedOnMalformedArchives(t *testing.T) {
	good := archive(t, file("a", strings.Repeat("x", 2000), 0o600, 0, 0), file("b", "y", 0o600, 0, 0))
	tests := map[string][]byte{
		"truncated in a header":  good[:300],
		"truncated in a body":    good[:512+700],
		"missing trailer":        good[:len(good)-1024],
		"half a trailer":         good[:len(good)-512],
		"ragged length":          good[:len(good)-100],
		"garbage header":         bytes.Repeat([]byte{0xff}, 1024),
		"trailing garbage":       append(append([]byte(nil), good...), []byte("junk")...),
		"data after the trailer": append(append([]byte(nil), good...), append(make([]byte, 512), bytes.Repeat([]byte("z"), 512)...)...),
		"path climbing out":      archive(t, file("../escape", "x", 0o600, 0, 0)),
		"embedded climb":         archive(t, file("a/../../escape", "x", 0o600, 0, 0)),
		"empty name":             archive(t, file("", "x", 0o600, 0, 0)),
		"hard link escaping":     archive(t, member{hdr: tar.Header{Typeflag: tar.TypeLink, Name: "l", Linkname: "../etc/passwd"}}),
		"unsupported type":       archive(t, member{hdr: tar.Header{Typeflag: tar.TypeCont, Name: "c"}}),
	}
	for name, input := range tests {
		t.Run(name, func(t *testing.T) {
			if m, err := TarManifest(bytes.NewReader(input)); err == nil {
				t.Errorf("accepted: %+v", m)
			}
		})
	}
}

func TestManifestAcceptsPaddedRecordsLikeGNUTar(t *testing.T) {
	padded := append(archive(t, file("a", "x", 0o600, 0, 0)), make([]byte, 10240-2048)...)
	if m := manifestOf(t, padded); m.Count != 1 {
		t.Errorf("manifest = %+v", m)
	}
}

func TestManifestDropsEntryDetailAboveItsLimitButKeepsTheDigest(t *testing.T) {
	members := make([]member, ManifestDetailLimit+1)
	for i := range members {
		members[i] = file(strings.Repeat("a", 1+i%7)+"/"+string(rune('a'+i%26))+strings.Repeat("b", i/26), "", 0o600, 0, 0)
	}
	m := manifestOf(t, archive(t, members...))
	if m.Count != ManifestDetailLimit+1 || m.Entries != nil || m.Digest == "" {
		t.Errorf("count=%d entries=%d digest=%q", m.Count, len(m.Entries), m.Digest)
	}
}
