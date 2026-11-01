package transport

import (
	"bytes"
	"context"
	"errors"
	"io"
	"sync/atomic"
	"testing"
)

// fakeStream is an in-memory Stream: exports read from src, imports write to
// sink. It records the order of Close, Abort and Wait.
type fakeStream struct {
	src      io.Reader
	sink     bytes.Buffer
	writeErr error
	exit     int
	tail     string
	waitErr  error

	closed, aborted  atomic.Bool
	closedBeforeWait bool
	waited           atomic.Bool
}

func (f *fakeStream) Read(p []byte) (int, error) {
	if f.aborted.Load() {
		return 0, ErrStreamAborted
	}
	return f.src.Read(p)
}

func (f *fakeStream) Write(p []byte) (int, error) {
	if f.writeErr != nil {
		return 0, f.writeErr
	}
	return f.sink.Write(p)
}

func (f *fakeStream) Close() error { f.closed.Store(true); return nil }
func (f *fakeStream) Abort()       { f.aborted.Store(true) }
func (f *fakeStream) Wait() (int, string, error) {
	f.closedBeforeWait = f.closed.Load()
	f.waited.Store(true)
	return f.exit, f.tail, f.waitErr
}

func exportOf(s string) *fakeStream { return &fakeStream{src: bytes.NewReader([]byte(s))} }

func TestCopyVolumeMovesTheBytesAndClosesTheImporterBeforeWaiting(t *testing.T) {
	exp, imp := exportOf("tar-bytes"), &fakeStream{}
	n, err := CopyVolume(context.Background(), exp, imp, 100)
	if err != nil || n != 9 || imp.sink.String() != "tar-bytes" {
		t.Fatalf("n=%d err=%v sink=%q", n, err, imp.sink.String())
	}
	if !imp.closedBeforeWait {
		t.Error("the importer was waited before its stdin was closed")
	}
	if exp.aborted.Load() || imp.aborted.Load() || !exp.waited.Load() || !imp.waited.Load() {
		t.Error("a successful copy must wait both ends and abort neither")
	}
}

func TestCopyVolumeFailsWhenEitherEndExitsNonZeroAndAbortsTheOther(t *testing.T) {
	tests := map[string]struct {
		export, imp *fakeStream
		side        string
		wantAborted string // which end must have been aborted
	}{
		"export exits 1": {&fakeStream{src: bytes.NewReader([]byte("x")), exit: 1, tail: "no such container"}, &fakeStream{}, "export", "import"},
		"import exits 2": {exportOf("x"), &fakeStream{exit: 2, tail: "read-only"}, "import", ""},
		"export lost the session": {
			&fakeStream{src: bytes.NewReader([]byte("x")), waitErr: errors.New("lost")}, &fakeStream{}, "export", "import",
		},
		"import lost the session": {exportOf("x"), &fakeStream{waitErr: errors.New("lost")}, "import", ""},
		"import write fails": {
			exportOf("x"), &fakeStream{writeErr: io.ErrClosedPipe, exit: 0}, "import", "export",
		},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			_, err := CopyVolume(context.Background(), tc.export, tc.imp, 100)
			var ce *CopyError
			if !errors.As(err, &ce) || ce.Side != tc.side {
				t.Fatalf("err = %v, want a CopyError at the %s", err, tc.side)
			}
			if !tc.export.waited.Load() || !tc.imp.waited.Load() {
				t.Error("both ends must be settled before CopyVolume returns")
			}
			if tc.wantAborted == "import" && !tc.imp.aborted.Load() || tc.wantAborted == "export" && !tc.export.aborted.Load() {
				t.Errorf("the %s was not aborted", tc.wantAborted)
			}
		})
	}
}

func TestCopyVolumeCarriesTheTailsOfBothEnds(t *testing.T) {
	_, err := CopyVolume(context.Background(), &fakeStream{src: bytes.NewReader(nil), exit: 1, tail: "export said"}, &fakeStream{tail: "import said"}, 10)
	var ce *CopyError
	if !errors.As(err, &ce) || ce.ExportTail != "export said" || ce.ImportTail != "import said" || ce.ExportExit != 1 {
		t.Fatalf("err = %#v", err)
	}
}

func TestCopyVolumeStopsAtItsCeiling(t *testing.T) {
	exp, imp := exportOf("0123456789"), &fakeStream{}
	n, err := CopyVolume(context.Background(), exp, imp, 9)
	if !errors.Is(err, ErrStreamCeiling) || n > 9 || imp.sink.Len() > 9 {
		t.Fatalf("n=%d err=%v written=%d", n, err, imp.sink.Len())
	}
	if !exp.aborted.Load() || !imp.aborted.Load() {
		t.Error("exceeding the ceiling must abort both ends")
	}
	if _, err := CopyVolume(context.Background(), exportOf("0123456789"), &fakeStream{}, 10); err != nil {
		t.Errorf("exactly the ceiling: %v", err)
	}
}

func TestCopyVolumeAbortsBothWhenTheContextEnds(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	exp, imp := exportOf("x"), &fakeStream{}
	_, err := CopyVolume(ctx, exp, imp, 10)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v", err)
	}
	if !exp.aborted.Load() || !imp.aborted.Load() {
		t.Error("a cancelled copy must abort both ends")
	}
}
