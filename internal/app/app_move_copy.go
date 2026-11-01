package app

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/autarquico/supermgmt/internal/database"
	"github.com/autarquico/supermgmt/internal/deployments/compose"
	"github.com/autarquico/supermgmt/internal/domain"
	smerr "github.com/autarquico/supermgmt/internal/errors"
	"github.com/autarquico/supermgmt/internal/jobs"
	"github.com/autarquico/supermgmt/internal/transport"
	"github.com/autarquico/supermgmt/internal/transport/ssh/templates"
)

// The copy of one volume (spec §5): the volume is exported from A's container and imported into B's through the
// daemon, then exported again from B and compared by manifest. A volume is never imported twice into the same
// volume: a failed attempt is replaced, which removes B's containers, the volume (only if this move created it) and
// creates them again.
const (
	moveCopyAttempts  = 3
	moveStreamIdle    = 2 * time.Minute
	moveMinCopyTime   = 10 * time.Minute
	moveCopyRate      = 5 << 20 // bytes per second a deadline assumes
	moveCeilingMargin = 64 << 20
	// moveOpenBound is the most opening the import stream may take. The node-side timeout starts once the command
	// does, so the recorded deadline includes it: "deadline passed" then proves the import command ended.
	moveOpenBound = time.Minute
)

// copyBounds are the node-side deadline of one copy and the most bytes it may carry for a volume of size bytes.
func copyBounds(size int64) (time.Duration, int64) {
	timeout := moveMinCopyTime + time.Duration(size/moveCopyRate)*time.Second
	return min(timeout, templates.MaxStreamDeadline-templates.KillAfter), size + size/4 + moveCeilingMargin
}

// volumeFailure is the failure of one attempt to copy a volume, which replacement answers. stopped says that the
// import is proven to have ended; otherwise the volume waits for the deadline of its import.
type volumeFailure struct {
	volume  string
	cause   error
	stopped bool
}

func (f *volumeFailure) Error() string { return fmt.Sprintf("volume %s: %v", f.volume, f.cause) }
func (f *volumeFailure) Unwrap() error { return f.cause }

// copyData copies every volume of the map, one at a time, and records the phase.
func (r *moveRun) copyData(ctx context.Context) error {
	names, err := r.volumeNames(ctx)
	if err != nil {
		return err
	}
	for _, name := range names {
		if err := r.copyVolume(ctx, name); err != nil {
			return err
		}
	}
	return r.advance(ctx, database.AppMoveDataCopied, "")
}

// copyVolume brings one volume to verified from whatever state a former run left it in.
func (r *moveRun) copyVolume(ctx context.Context, name string) error {
	for {
		v, err := database.GetAppMoveVolume(ctx, r.h.cfg.DB.Reader(), r.move.ID, name)
		if err != nil {
			return err
		}
		switch v.State {
		case database.AppMoveVolumeVerified:
			return nil
		case database.AppMoveVolumePending:
			err = r.importVolume(ctx, v)
		case database.AppMoveVolumeImported:
			err = r.verifyVolume(ctx, v)
		case database.AppMoveVolumeImporting:
			err = &volumeFailure{volume: name, cause: errors.New("an import of an earlier run has an unknown outcome")}
		}
		var failed *volumeFailure
		switch {
		case err == nil:
		case ctx.Err() != nil || !errors.As(err, &failed):
			return err
		case v.Attempt >= moveCopyAttempts:
			return smerr.New(smerr.CodeDeploymentFailed, "", fmt.Sprintf(
				"volume %s could not be copied in %d attempts: %v", name, moveCopyAttempts, failed.cause))
		default:
			if err := r.replaceVolume(ctx, failed); err != nil {
				return err
			}
		}
	}
}

// importVolume streams the volume from A's container into B's, under an import intent whose deadline is recorded
// first, and leaves the volume imported when both ends exited 0.
func (r *moveRun) importVolume(ctx context.Context, v database.AppMoveVolume) error {
	sizes, _, err := r.sourceSizes(ctx)
	if err != nil {
		return err
	}
	timeout, ceiling := copyBounds(sizes[v.VolumeName])
	args := r.streamArgs(v, timeout)
	exportCmd, err := templates.RenderStream("docker.volume_export", args)
	if err != nil {
		return smerr.New(smerr.CodeInternal, "", "the volume export cannot be rendered for the node")
	}
	importCmd, err := templates.RenderStream("docker.volume_import", args)
	if err != nil {
		return smerr.New(smerr.CodeInternal, "", "the volume import cannot be rendered for the node")
	}
	opts := transport.StreamOptions{Total: timeout + templates.KillAfter, Idle: moveStreamIdle, Ceiling: ceiling}
	// The export is a read with no intent: if it cannot open, nothing has happened on B and no import is recorded.
	exp, err := r.h.conn.OpenStream(ctx, r.a.node, r.a.setup, exportCmd, opts)
	if err != nil {
		return err
	}
	// The node-side timeout starts when the command does, and the command is not opened after openBy.
	openBy := r.h.cfg.Clock.Now().Add(moveOpenBound)
	deadline := openBy.Add(timeout + templates.KillAfter)
	err = r.fenced(ctx, func(ctx context.Context, tx *database.Tx) error {
		_, err := database.BeginAppMoveVolumeImport(ctx, tx, r.move.ID, v.VolumeName, v.Attempt, deadline, r.h.cfg.Clock.Now())
		return err
	})
	if err != nil {
		abortStream(exp)
		return err
	}
	ledger := deployLedger{h: *r.h.dep, lease: r.lease}
	pre, _ := json.Marshal(map[string]any{
		"move": r.move.ID, "node": r.b.node.ID, "volume": v.VolumeName, "attempt": v.Attempt, "container": args["container"], "mount": args["mount"],
	})
	intent, err := ledger.RecordIntent(ctx, jobs.NewIntent{
		Step: fmt.Sprintf("copy-%s-%d", v.VolumeName, v.Attempt), Operation: "docker.volume_import",
		TargetType: string(domain.ResourceDeployment), TargetID: r.bDep.ID.String(), PreState: pre, DeadlineAt: deadline,
	})
	if err != nil {
		abortStream(exp)
		return err
	}
	if err := ledger.MarkDispatched(ctx, intent); err != nil {
		abortStream(exp)
		return err
	}

	if !openBy.After(r.h.cfg.Clock.Now()) {
		return r.importNeverOpened(ctx, ledger, intent, exp, v, errors.New("the time to open the import ran out before it was opened"))
	}
	// openBy bounds only the opening: the established stream is supervised by ctx and its own deadlines.
	opts.OpenBy = openBy
	imp, err := r.h.conn.OpenStream(ctx, r.b.node, r.b.setup, importCmd, opts)
	if err != nil {
		if !errors.Is(err, transport.ErrNotStarted) {
			// The command may have been sent: it ends by the recorded deadline, which the replacement waits for.
			abortStream(exp)
			return &volumeFailure{volume: v.VolumeName, cause: err}
		}
		return r.importNeverOpened(ctx, ledger, intent, exp, v, err)
	}
	if r.h.cfg.Clock.Now().After(openBy) {
		// Opened too late for the recorded deadline to cover the node-side timeout: end it, and wait for the deadline.
		abortStream(exp)
		abortStream(imp)
		return &volumeFailure{volume: v.VolumeName, cause: errors.New("the import stream opened after the time allowed for it")}
	}

	tee := newManifestTee(exp)
	_, copyErr := transport.CopyVolume(ctx, tee, imp, ceiling)
	manifest, manifestErr := tee.finish(copyErr)
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if copyErr != nil {
		stopped := importEnded(copyErr)
		if stopped {
			var ce *transport.CopyError
			errors.As(copyErr, &ce)
			if cerr := ledger.CompleteIntent(ctx, intent, jobs.OutcomeFailed, commandExitEvidence(jobs.OutcomeFailed, ce.ImportExit)); cerr != nil {
				return cerr
			}
		}
		return &volumeFailure{volume: v.VolumeName, cause: copyErr, stopped: stopped}
	}
	// Both ends exited 0: the import ran to its end whatever the archive holds.
	if err := ledger.CompleteIntent(ctx, intent, jobs.OutcomeSucceeded, commandExitEvidence(jobs.OutcomeSucceeded, 0)); err != nil {
		return err
	}
	if manifestErr != nil {
		return &volumeFailure{volume: v.VolumeName, cause: fmt.Errorf("the exported archive cannot be verified: %w", manifestErr), stopped: true}
	}
	return r.fenced(ctx, func(ctx context.Context, tx *database.Tx) error {
		_, err := database.CompleteAppMoveVolumeImport(ctx, tx, r.move.ID, v.VolumeName, v.Attempt, manifest.Bytes, manifest.Digest, r.h.cfg.Clock.Now())
		return err
	})
}

// importNeverOpened settles an import whose command is proven not to have been sent.
func (r *moveRun) importNeverOpened(ctx context.Context, ledger deployLedger, intent domain.ID, exp transport.Stream, v database.AppMoveVolume, cause error) error {
	abortStream(exp)
	if err := ledger.CompleteIntent(ctx, intent, jobs.OutcomeFailed, commandExitEvidence(jobs.OutcomeFailed, 0)); err != nil {
		return err
	}
	return &volumeFailure{volume: v.VolumeName, cause: cause, stopped: true}
}

func abortStream(st transport.Stream) {
	st.Abort()
	_, _, _ = st.Wait()
}

// importEnded reports whether a failed copy proves the import command ended: the importer's exit status is known and
// not zero. Anything else (an aborted or lost session, a limit) leaves its outcome unknown.
func importEnded(err error) bool {
	var ce *transport.CopyError
	return errors.As(err, &ce) && ce.ImportExit != 0
}

func (r *moveRun) streamArgs(v database.AppMoveVolume, timeout time.Duration) map[string]string {
	return map[string]string{
		"container": fmt.Sprintf("%s-%s-1", r.target.ComposeProject, v.Service),
		"mount":     v.MountTarget,
		"deadline":  templates.DeadlineArg(timeout),
	}
}

// verifyVolume exports the volume again from B and records it verified when its manifest is A's.
func (r *moveRun) verifyVolume(ctx context.Context, v database.AppMoveVolume) error {
	sizes, _, err := r.sourceSizes(ctx)
	if err != nil {
		return err
	}
	timeout, ceiling := copyBounds(sizes[v.VolumeName])
	cmd, err := templates.RenderStream("docker.volume_export", r.streamArgs(v, timeout))
	if err != nil {
		return smerr.New(smerr.CodeInternal, "", "the volume export cannot be rendered for the node")
	}
	st, err := r.h.conn.OpenStream(ctx, r.b.node, r.b.setup, cmd, transport.StreamOptions{Total: timeout + templates.KillAfter, Idle: moveStreamIdle, Ceiling: ceiling})
	if err != nil {
		return err
	}
	got, readErr := transport.TarManifest(st)
	if readErr != nil {
		st.Abort()
	}
	exit, tail, waitErr := st.Wait()
	if err := ctx.Err(); err != nil {
		return err
	}
	// The export is a read and B's import has ended, so any failure of it fails the attempt and the volume is replaced.
	switch {
	case readErr != nil:
		return &volumeFailure{volume: v.VolumeName, cause: fmt.Errorf("the archive from B cannot be read: %w", readErr), stopped: true}
	case waitErr != nil:
		return &volumeFailure{volume: v.VolumeName, cause: fmt.Errorf("the export from B failed: %w", waitErr), stopped: true}
	case exit != 0:
		return &volumeFailure{volume: v.VolumeName, cause: fmt.Errorf("the export from B exited %d (%s)", exit, tail), stopped: true}
	case got.Digest != v.SourceDigest:
		return &volumeFailure{volume: v.VolumeName, stopped: true, cause: fmt.Errorf(
			"the destination holds %d bytes in %d entries that differ from the %d bytes the source exported", got.Bytes, got.Count, v.SourceBytes)}
	}
	return r.fenced(ctx, func(ctx context.Context, tx *database.Tx) error {
		_, err := database.VerifyAppMoveVolume(ctx, tx, r.move.ID, v.VolumeName, v.Attempt, got.Bytes, got.Digest, r.h.cfg.Clock.Now())
		return err
	})
}

// replaceVolume answers a failed attempt: once the import is proven stopped, B's containers are removed keeping
// their volumes, the volume is removed (only if this move created it) and the arrangement is created again, which
// leaves the volume empty. Only then is the attempt counted, so a crash in between replaces again.
func (r *moveRun) replaceVolume(ctx context.Context, failed *volumeFailure) error {
	v, err := database.GetAppMoveVolume(ctx, r.h.cfg.DB.Reader(), r.move.ID, failed.volume)
	if err != nil {
		return err
	}
	if v.State == database.AppMoveVolumeImporting && !failed.stopped {
		if err := r.awaitImportEnd(ctx, v); err != nil {
			return err
		}
	}
	if !v.CreatedByMove {
		return smerr.New(smerr.CodeConflict, "", fmt.Sprintf("volume %s was not created by this move and is not removed", v.VolumeName))
	}
	j := r.destJob()
	if err := r.mustSend(ctx, r.b, j.dep.ID, "replace-down", "compose.down", j.dir().args(), true); err != nil {
		return err
	}
	found, err := r.existingVolumes(ctx, r.b, []string{v.VolumeName})
	if err != nil {
		return err
	}
	if existing, exists := found[v.VolumeName]; exists {
		if err := r.requireOwnedVolume(existing); err != nil {
			return err
		}
		if err := r.mustSend(ctx, r.b, j.dep.ID, "replace-volume-rm", "docker.volume_rm", map[string]string{"volume": v.VolumeName}, false); err != nil {
			return err
		}
	}
	if err := r.mustSend(ctx, r.b, j.dep.ID, "replace-create", "compose.create", j.dir().args(), true); err != nil {
		return err
	}
	return r.fenced(ctx, func(ctx context.Context, tx *database.Tx) error {
		_, err := database.ResetAppMoveVolume(ctx, tx, r.move.ID, v.VolumeName, v.Attempt, v.State, r.h.cfg.Clock.Now())
		return err
	})
}

// requireOwnedVolume refuses to remove a volume of B that does not bear this target's owner label: the row says this
// move created it, but a volume that appeared by another hand under the same name is not the move's to delete.
func (r *moveRun) requireOwnedVolume(v templates.Volume) error {
	if v.Labels[compose.LabelOwner] != r.target.ID.String() {
		return smerr.New(smerr.CodeConflict, "", fmt.Sprintf("volume %s on node %s does not bear this target's owner label and is not removed", v.Name, r.b.node.Name))
	}
	return nil
}

// awaitImportEnd leaves an import of unknown outcome alone until its deadline, which includes the kill margin, has
// passed: until then it may still be writing. A job that cannot wait that long ends with an unknown outcome.
func (r *moveRun) awaitImportEnd(ctx context.Context, v database.AppMoveVolume) error {
	if v.ImportDeadlineAt == nil {
		return fmt.Errorf("%w: volume %s is importing with no deadline", jobs.ErrOutcomeUnknown, v.VolumeName)
	}
	clock := r.h.cfg.Clock
	if wait := v.ImportDeadlineAt.Sub(clock.Now()); wait > 0 {
		r.h.dep.sleep(ctx, wait)
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if clock.Now().Before(*v.ImportDeadlineAt) {
		return fmt.Errorf("%w: the import of volume %s may still be running until %s",
			jobs.ErrOutcomeUnknown, v.VolumeName, v.ImportDeadlineAt.UTC().Format(time.RFC3339))
	}
	return nil
}

// ---- the manifest of what A exports ----------------------------------------------------------------------------

// manifestTee hands the manifest reader every byte the copy reads from the export, so the archive that was sent is
// the archive that is compared.
type manifestTee struct {
	transport.Stream
	w        *io.PipeWriter
	done     chan struct{}
	manifest transport.Manifest
	err      error
}

func newManifestTee(s transport.Stream) *manifestTee {
	pr, pw := io.Pipe()
	t := &manifestTee{Stream: s, w: pw, done: make(chan struct{})}
	go func() {
		defer close(t.done)
		t.manifest, t.err = transport.TarManifest(pr)
		_, _ = io.Copy(io.Discard, pr) // never block the copy, whatever the archive looks like
	}()
	return t
}

func (t *manifestTee) Read(p []byte) (int, error) {
	n, err := t.Stream.Read(p)
	if n > 0 {
		_, _ = t.w.Write(p[:n])
	}
	if err != nil && !errors.Is(err, io.EOF) {
		_ = t.w.CloseWithError(err)
	}
	if errors.Is(err, io.EOF) {
		_ = t.w.Close()
	}
	return n, err
}

// finish ends the archive (with copyErr when the copy failed) and returns its manifest.
func (t *manifestTee) finish(copyErr error) (transport.Manifest, error) {
	if copyErr != nil {
		_ = t.w.CloseWithError(copyErr)
	} else {
		_ = t.w.Close()
	}
	<-t.done
	return t.manifest, t.err
}
