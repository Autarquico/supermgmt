package installer

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io/fs"
	"time"
)

func (w *world) AppendSync(p string, line []byte) error {
	w.files[p] = append(append([]byte{}, w.files[p]...), line...)
	w.record("append ", p)
	return nil
}

func (w *world) SyncDir(dir string) error { w.record("syncdir ", dir); return nil }

func (w *world) Rename(oldPath, newPath string) error {
	b, ok := w.files[oldPath]
	if !ok {
		return fs.ErrNotExist
	}
	w.files[newPath], w.modes[newPath], w.owners[newPath] = b, w.modes[oldPath], w.owners[oldPath]
	delete(w.files, oldPath)
	w.record("rename ", oldPath, newPath)
	return nil
}

func (w *world) Link(oldPath, newPath string) error {
	b, ok := w.files[oldPath]
	if !ok {
		return fs.ErrNotExist
	}
	if _, taken := w.files[newPath]; taken {
		return fs.ErrExist
	}
	w.files[newPath] = b
	w.record("link ", oldPath, newPath)
	return nil
}

func (w *world) Hash(p string) (string, error) {
	b, ok := w.files[p]
	if !ok {
		return "", fs.ErrNotExist
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:]), nil
}

func (s fakeServices) Load(_ context.Context, u Unit) error {
	s.w.record(s.prefix+"load ", u.Name)
	return nil
}

func (s fakeServices) Stop(_ context.Context, u Unit) error {
	s.w.record(s.prefix+"stop ", u.Name)
	return nil
}

func (s fakeServices) Disable(_ context.Context, u Unit) error {
	s.w.record(s.prefix+"disable ", u.Name)
	return nil
}

func (s fakeServices) Hold(_ context.Context, u Unit) error {
	s.w.record(s.prefix+"hold ", u.Name)
	return nil
}

func (s fakeServices) WaitStopped(_ context.Context, u Unit, _ time.Duration) error {
	s.w.record(s.prefix+"waitstopped ", u.Name)
	return nil
}
