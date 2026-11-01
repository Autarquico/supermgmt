package transport

import (
	"bytes"
	"testing"
)

func FuzzTarManifest(f *testing.F) {
	for _, seed := range [][]byte{
		archive(f, dir("./", 0o755, 0, 0), file("a/b.txt", "hello", 0o600, 1000, 1000), symlink("l", "a/b.txt")),
		archive(f),
		{},
		bytes.Repeat([]byte{0}, 1024),
		bytes.Repeat([]byte{'x'}, 600),
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, in []byte) {
		first, err := TarManifest(bytes.NewReader(in))
		if err != nil {
			return
		}
		again, err := TarManifest(bytes.NewReader(in))
		if err != nil || again.Digest != first.Digest || again.Count != first.Count || again.Bytes != first.Bytes {
			t.Errorf("manifest of the same archive differs: %+v vs %+v (%v)", first, again, err)
		}
		if first.Count < 0 || first.Bytes < 0 || first.Digest == "" {
			t.Errorf("manifest %+v is malformed", first)
		}
	})
}
