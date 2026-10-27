package ssh

import (
	"io/fs"
	"syscall"
	"testing"
	"time"
)

type dirInfo struct {
	mode fs.FileMode
	uid  uint32
}

func (d dirInfo) Name() string       { return "dir" }
func (d dirInfo) Size() int64        { return 0 }
func (d dirInfo) Mode() fs.FileMode  { return fs.ModeDir | d.mode }
func (d dirInfo) ModTime() time.Time { return time.Time{} }
func (d dirInfo) IsDir() bool        { return true }
func (d dirInfo) Sys() any           { return &syscall.Stat_t{Uid: d.uid} }

func TestRootsStickyTmpIsASafeDirectory(t *testing.T) {
	if !directorySafe(dirInfo{mode: 0o777 | fs.ModeSticky, uid: 0}) {
		t.Error("root's /tmp (1777) was judged replaceable by others")
	}
	if directorySafe(dirInfo{mode: 0o777, uid: 0}) {
		t.Error("a root-owned directory others can write without the sticky bit was judged safe")
	}
	if directorySafe(dirInfo{mode: 0o775, uid: 0}) {
		t.Error("a root-owned group-writable directory was judged safe")
	}
}
