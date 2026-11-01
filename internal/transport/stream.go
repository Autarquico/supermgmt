package transport

import (
	"context"
	"errors"
	"fmt"
	"io"
	"time"
)

// StreamOptions bound one stream. All three are required: a stream that may
// run forever, or move without limit, is refused at open.
type StreamOptions struct {
	// Total ends the stream however much it still moves.
	Total time.Duration
	// Idle ends a stream that moved no byte for this long (a blocked peer).
	Idle time.Duration
	// Ceiling is the most bytes the stream may carry in its direction; the
	// byte after it aborts the stream.
	Ceiling int64
}

// Valid reports why the options cannot bound a stream, or nil.
func (o StreamOptions) Valid() error {
	switch {
	case o.Total <= 0 || o.Idle <= 0 || o.Ceiling <= 0:
		return errors.New("a stream needs a total deadline, an idle deadline and a byte ceiling")
	case o.Idle > o.Total:
		return errors.New("the idle deadline exceeds the total deadline")
	}
	return nil
}

// Typed failures of a stream, so callers can tell a limit from a lost session.
var (
	ErrStreamDirection = errors.New("stream: wrong direction")
	ErrStreamTotal     = errors.New("stream: total deadline exceeded")
	ErrStreamIdle      = errors.New("stream: idle deadline exceeded")
	ErrStreamCeiling   = errors.New("stream: byte ceiling exceeded")
	ErrStreamAborted   = errors.New("stream: aborted")
)

// Stream is one remote command whose stdout (an export) or stdin (an import)
// the caller moves itself, bytes untouched. It is binary-transparent and keeps
// no more than one copy buffer in memory.
//
// A stream holds a session slot and a connection lease from open until the
// remote command ends or the stream is aborted, whatever happens in between:
// the total deadline guarantees that point is reached.
type Stream interface {
	// Read returns the remote stdout; an import has none.
	Read(p []byte) (int, error)
	// Write feeds the remote stdin; an export has none.
	Write(p []byte) (int, error)
	// Close ends the caller's input (EOF on the remote stdin). It does not stop
	// the command and is safe to call repeatedly and concurrently.
	Close() error
	// Abort ends the command now, whatever it is doing. Safe at any time, any
	// number of times.
	Abort()
	// Wait blocks until the command has ended and the session is released. exit
	// is the remote exit status; stderrTail is its last stderr, bounded and
	// sanitised. err is non-nil when no trustworthy exit status exists: the
	// session was lost, a limit was hit or the stream was aborted.
	Wait() (exit int, stderrTail string, err error)
}

// CopyError says which end of a volume copy failed and what each said.
type CopyError struct {
	Side       string // "export" or "import"
	ExportExit int
	ImportExit int
	ExportTail string
	ImportTail string
	Cause      error
}

func (e *CopyError) Error() string {
	msg := fmt.Sprintf("volume copy failed at the %s", e.Side)
	if e.Cause != nil {
		msg += ": " + e.Cause.Error()
	}
	if e.Side == "export" && e.ExportTail != "" {
		msg += " (" + e.ExportTail + ")"
	}
	if e.Side == "import" && e.ImportTail != "" {
		msg += " (" + e.ImportTail + ")"
	}
	return msg
}

func (e *CopyError) Unwrap() error { return e.Cause }

// CopyVolume pipes the export's tar into the import and returns the bytes
// moved. Success means both ends exited 0: the importer's stdin is closed
// before waiting, so it sees EOF; on any failure, and when ctx ends, both
// streams are aborted. Both are always settled (Waited) before it returns, so
// their session slots are free.
func CopyVolume(ctx context.Context, export, imp Stream, ceiling int64) (int64, error) {
	stop := context.AfterFunc(ctx, func() { export.Abort(); imp.Abort() })
	defer stop()

	sink := &recordingWriter{w: imp}
	n, copyErr := io.Copy(sink, &ceilingReader{r: export, left: ceiling})
	if copyErr == nil && ctx.Err() != nil {
		copyErr = context.Cause(ctx)
	}
	if copyErr == nil {
		copyErr = imp.Close()
		sink.err = copyErr
	}
	if copyErr != nil {
		export.Abort()
		imp.Abort()
	}
	ee, et, eerr := export.Wait()
	if eerr != nil || ee != 0 {
		imp.Abort()
	}
	ie, it, ierr := imp.Wait()

	fail := &CopyError{ExportExit: ee, ImportExit: ie, ExportTail: et, ImportTail: it}
	switch {
	case ctx.Err() != nil:
		fail.Side, fail.Cause = "export", context.Cause(ctx)
	case sink.err != nil:
		fail.Side, fail.Cause = "import", sink.err
	case copyErr != nil || eerr != nil || ee != 0:
		fail.Side, fail.Cause = "export", firstErr(copyErr, eerr, exitErr(ee))
	case ierr != nil || ie != 0:
		fail.Side, fail.Cause = "import", firstErr(ierr, exitErr(ie))
	default:
		return n, nil
	}
	return n, fail
}

func exitErr(status int) error {
	if status == 0 {
		return nil
	}
	return fmt.Errorf("exit status %d", status)
}

func firstErr(errs ...error) error {
	for _, err := range errs {
		if err != nil {
			return err
		}
	}
	return nil
}

var errCeiling = fmt.Errorf("%w: the copy exceeds its ceiling", ErrStreamCeiling)

// recordingWriter remembers a write failure, which io.Copy does not say apart
// from a read failure.
type recordingWriter struct {
	w   io.Writer
	err error
}

func (r *recordingWriter) Write(p []byte) (int, error) {
	n, err := r.w.Write(p)
	if err != nil {
		r.err = err
	}
	return n, err
}

// ceilingReader fails, instead of returning, the byte after its ceiling.
type ceilingReader struct {
	r    io.Reader
	left int64
}

func (c *ceilingReader) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	c.left -= int64(n)
	if c.left < 0 {
		return 0, errCeiling
	}
	return n, err
}
