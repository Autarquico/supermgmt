package app

import (
	"archive/tar"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"slices"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/autarquico/supermgmt/internal/api/wire"
	"github.com/autarquico/supermgmt/internal/database"
	"github.com/autarquico/supermgmt/internal/deployments"
	"github.com/autarquico/supermgmt/internal/deployments/compose"
	"github.com/autarquico/supermgmt/internal/domain"
	smerr "github.com/autarquico/supermgmt/internal/errors"
	"github.com/autarquico/supermgmt/internal/jobs"
	"github.com/autarquico/supermgmt/internal/transport"
	"github.com/autarquico/supermgmt/internal/transport/ssh"
	"github.com/autarquico/supermgmt/internal/transport/ssh/templates"
)

// ---- a pair of simulated nodes -----------------------------------------------------------------------------------

const (
	moveStatefulCompose = `
services:
  web:
    image: ghcr.io/acme/web:placeholder
    environment:
      DATABASE_URL: ${secret:db}
    ports:
      - {target: 8080, published: 8080, host_ip: 127.0.0.1}
    volumes:
      - {type: volume, source: data, target: /data}
      - {type: volume, source: cache, target: /var/cache/web}
  redis:
    image: docker.io/library/redis@sha256:3333333333333333333333333333333333333333333333333333333333333333
    volumes:
      - {type: volume, source: data, target: /data, read_only: true}
volumes:
  data: {}
  cache: {}
`
	moveLimitedCompose = `
services:
  web:
    image: ghcr.io/acme/web:placeholder
    environment:
      DATABASE_URL: ${secret:db}
    mem_limit: 512m
    ports:
      - {target: 8080, published: 8080, host_ip: 127.0.0.1}
`
)

var simRestart = regexp.MustCompile(`--restart '([a-z-]+)' -- '([0-9a-f]+)'`)

var simUUID = regexp.MustCompile(`[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}`)

// moveSim is one node as a move sees it: Compose containers with a state, named volumes holding files, and the
// answers of the reads a move makes. A and B are two of them, switched by node ID.
type moveSim struct {
	w     *runWorld
	label string
	node  *fakeNode

	mu         sync.Mutex
	state      string // none, created, running or exited
	deployment domain.ID
	volumes    map[string]map[string]string
	memTotal   int64
	cpus       int
	free       int64
	noPlatform bool
	marker     string            // the answer to marker.state; "" means the command finished with exit 0
	imports    map[string]int    // applied imports per volume
	exports    map[string]int    // export sessions opened per volume
	restart    map[string]string // restart policy by container ID, as docker update --restart set it
	foreign    map[string]bool   // volumes that bear no owner label
}

func newMoveSim(w *runWorld, label string, id domain.ID) *moveSim {
	s := &moveSim{
		w: w, label: label, node: newFakeNode(w.t), state: "none", volumes: map[string]map[string]string{},
		memTotal: 8 << 30, cpus: 4, free: 1 << 40, imports: map[string]int{}, exports: map[string]int{},
		restart: map[string]string{}, foreign: map[string]bool{},
	}
	s.node.fallback = s.handle
	w.dialer.route(id, s.node)
	return s
}

func (s *moveSim) volumeFiles(name string) (map[string]string, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	files, ok := s.volumes[name]
	return copyFiles(files), ok
}

func copyFiles(in map[string]string) map[string]string {
	out := make(map[string]string, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}

func (s *moveSim) logf(format string, args ...any) {
	s.w.mu.Lock()
	defer s.w.mu.Unlock()
	s.w.log = append(s.w.log, s.label+" "+fmt.Sprintf(format, args...))
}

func (s *moveSim) services() []string {
	if s.w.stateful {
		return []string{"web", "redis"}
	}
	return []string{"web"}
}

// handle answers one rendered template.
func (s *moveSim) handle(c templates.Command) (transport.Result, error) {
	if s.w.before != nil && c.Mutating {
		s.w.before(s.label, c)
	}
	s.logf("%s", c.Template)
	res, err := s.answer(c)
	if err == nil && c.Mutating {
		err = s.w.afterDispatch(s, c)
	}
	return res, err
}

func ok(stdout string) (transport.Result, error) {
	return transport.Result{Stdout: []byte(stdout)}, nil
}

func exited(status int) (transport.Result, error) {
	return transport.Result{ExitStatus: status}, nil
}

func (s *moveSim) answer(c templates.Command) (transport.Result, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	switch c.Template {
	case "marker.state":
		if s.marker == "" {
			return ok("done 0\n")
		}
		return ok(s.marker)
	case "compose.ps_state":
		return ok(s.psState())
	case "compose.project_containers":
		if s.state == "none" {
			return ok("")
		}
		return ok(fmt.Sprintf(`[{"Config":{"Labels":{"%s":"%s"}},"HostConfig":{"PortBindings":{}}}]`, compose.LabelOwner, s.w.target.ID))
	case "compose.project_resources", "compose.listeners":
		return ok("")
	case "compose.docker_root":
		return ok("/var/lib/docker\n")
	case "compose.disk_free":
		return ok(preflightDF(s.free))
	case "compose.image_inspect":
		return exited(1)
	case "compose.image_size":
		if s.noPlatform {
			return exited(1)
		}
		return ok("1000\n")
	case "docker.info_resources":
		return ok(fmt.Sprintf(`{"NCPU":%d,"MemTotal":%d}`, s.cpus, s.memTotal))
	case "docker.volume_sizes":
		return ok(s.volumeSizes())
	case "docker.volume_inspect_many":
		return ok(s.inspectVolumes(c.Line))
	case "compose.pull", "compose.materialize":
		return exited(0)
	case "compose.verify":
		return s.w.verifyReply(c)
	case "compose.create":
		s.create(c.Line)
	case "docker.update_restart":
		match := simRestart.FindStringSubmatch(c.Line)
		if match == nil {
			s.w.t.Errorf("node %s: update_restart with no policy and container: %s", s.label, c.Line)
			return exited(2)
		}
		s.restart[match[2]] = match[1]
		s.logf("restart %s", match[1])
	case "compose.start":
		if s.state != "none" {
			s.state = "running"
		}
	case "compose.stop":
		if s.state == "running" {
			s.state = "exited"
		}
	case "compose.down":
		s.state = "none"
	case "docker.volume_rm":
		name := s.volumeIn(c.Line)
		if _, present := s.volumes[name]; !present {
			return exited(1)
		}
		delete(s.volumes, name)
	case "health.http":
		if s.w.hook != nil {
			s.w.hook()
		}
		return ok(s.w.healthAnswer(s))
	default:
		s.w.t.Errorf("node %s: unexpected template %s", s.label, c.Template)
		return exited(127)
	}
	return exited(0)
}

func (s *moveSim) create(line string) {
	if id := simUUID.FindString(line); id != "" {
		s.deployment = domain.ID(id)
	}
	if s.state == "none" {
		s.state = "created"
	}
	for _, name := range s.w.volumeNames() {
		if _, present := s.volumes[name]; !present {
			s.volumes[name] = map[string]string{"seeded-by-image": "1"}
		}
	}
}

func (s *moveSim) psState() string {
	if s.state == "none" {
		return ""
	}
	var out strings.Builder
	for _, service := range s.services() {
		name := fmt.Sprintf("%s-%s-1", s.w.project(), service)
		id := sha256.Sum256([]byte(s.label + name))
		labels := fmt.Sprintf("%s=%s,%s=%s,com.docker.compose.project=%s,com.docker.compose.service=%s",
			compose.LabelOwner, s.w.target.ID, compose.LabelDeployment, s.deployment, s.w.project(), service)
		fmt.Fprintf(&out, `{"ID":%q,"Names":%q,"State":%q,"Labels":%q}`+"\n", hex.EncodeToString(id[:]), name, s.state, labels)
	}
	return out.String()
}

// restartOf is the restart policy docker update last set on the container of service, or "" when none did.
func (s *moveSim) restartOf(service string) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	id := sha256.Sum256([]byte(s.label + fmt.Sprintf("%s-%s-1", s.w.project(), service)))
	return s.restart[hex.EncodeToString(id[:])]
}

func (s *moveSim) volumeSizes() string {
	var rows []string
	for name := range s.volumes {
		rows = append(rows, fmt.Sprintf(`{"Name":%q,"Size":"1MB"}`, name))
	}
	sort.Strings(rows)
	return `{"Volumes":[` + strings.Join(rows, ",") + `]}`
}

func (s *moveSim) inspectVolumes(line string) string {
	var rows []string
	for _, name := range s.w.volumeNames() {
		if _, present := s.volumes[name]; present && strings.Contains(line, name) {
			labels := fmt.Sprintf(`{%q:%q}`, compose.LabelOwner, s.w.target.ID)
			if s.foreign[name] {
				labels = "{}"
			}
			rows = append(rows, fmt.Sprintf(`{"Name":%q,"Driver":"local","Labels":%s}`, name, labels))
		}
	}
	return "[" + strings.Join(rows, ",") + "]"
}

func (s *moveSim) volumeIn(line string) string {
	for _, name := range s.w.volumeNames() {
		if strings.Contains(line, name) {
			return name
		}
	}
	return ""
}

// ---- streams ---------------------------------------------------------------------------------------------------

// streamFault makes the nth session of a kind on a node end badly.
type streamFault struct {
	label string // A or B
	kind  templates.StreamKind
	mount string
	nth   int
	mode  string // exit1, lost or corrupt
}

type simStream struct {
	s       *moveSim
	kind    templates.StreamKind
	volume  string
	mode    string
	reader  *bytes.Reader
	buf     bytes.Buffer
	aborted bool
	closed  bool
}

func (s *moveSim) openStream(c templates.Command) (transport.Stream, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	volume := ""
	mount := ""
	for m, name := range s.w.mounts {
		if strings.Contains(c.Line, m) {
			volume, mount = name, m
		}
	}
	if volume == "" {
		s.w.t.Errorf("node %s: stream %s names no known mount: %s", s.label, c.Template, c.Line)
	}
	st := &simStream{s: s, kind: c.Stream, volume: volume}
	if c.Stream == templates.StreamExport {
		s.exports[volume]++
		s.logf("export %s", mount)
		st.mode = s.w.faultFor(s.label, c.Stream, mount)
		files := s.volumes[volume]
		if files == nil {
			files = map[string]string{}
		}
		st.reader = bytes.NewReader(simTar(files))
		if st.mode == "garbage" {
			st.reader = bytes.NewReader(bytes.Repeat([]byte{'x'}, 2048))
		}
		return st, nil
	}
	s.logf("import %s", mount)
	st.mode = s.w.faultFor(s.label, c.Stream, mount)
	if s.w.tick("dispatch") {
		st.mode = "lost"
		s.w.stuck = true // the run ends with the outcome unknown, as a crash would
	}
	return st, nil
}

func (st *simStream) Read(p []byte) (int, error) { return st.reader.Read(p) }

func (st *simStream) Write(p []byte) (int, error) { return st.buf.Write(p) }

func (st *simStream) Close() error {
	st.closed = true
	return nil
}

func (st *simStream) Abort() { st.aborted = true }

func (st *simStream) Wait() (int, string, error) {
	if st.aborted {
		return 0, "", transport.ErrStreamAborted
	}
	if st.kind == templates.StreamExport {
		if st.s.label == "B" && st.s.w.afterVerify != nil {
			st.s.w.afterVerify()
		}
		if st.mode == "exit1" {
			return 1, "docker cp failed", nil
		}
		return 0, "", nil
	}
	st.s.mu.Lock()
	defer st.s.mu.Unlock()
	files, err := simUntar(st.buf.Bytes())
	if _, present := st.s.volumes[st.volume]; !present || err != nil {
		return 1, "no such container", nil
	}
	if st.mode == "exit1" {
		return 1, "docker cp failed", nil
	}
	if st.mode == "corrupt" {
		for _, path := range sortedKeys(files) {
			delete(files, path)
			break
		}
	}
	for path, content := range files {
		st.s.volumes[st.volume][path] = content
	}
	st.s.imports[st.volume]++
	if st.mode == "lost" {
		return 0, "", transport.ErrStreamAborted // the session ended with no exit status, after the data landed
	}
	return 0, "", nil
}

func simTar(files map[string]string) []byte {
	var b bytes.Buffer
	tw := tar.NewWriter(&b)
	for _, path := range sortedKeys(files) {
		_ = tw.WriteHeader(&tar.Header{Name: "./" + path, Mode: 0o600, Size: int64(len(files[path])), Uid: 1000, Gid: 1000, Typeflag: tar.TypeReg})
		_, _ = tw.Write([]byte(files[path]))
	}
	_ = tw.Close()
	return b.Bytes()
}

func simUntar(data []byte) (map[string]string, error) {
	files := map[string]string{}
	tr := tar.NewReader(bytes.NewReader(data))
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			return files, nil
		}
		if err != nil {
			return nil, err
		}
		content, err := io.ReadAll(tr)
		if err != nil {
			return nil, err
		}
		files[strings.TrimPrefix(hdr.Name, "./")] = string(content)
	}
}

// runDialer is the fake SSH pool with sessions that stream.
type runDialer struct {
	*fakeDialer
	w *runWorld
}

func (d runDialer) OpenStream(ctx context.Context, t ssh.Target, c templates.Command, _ transport.StreamOptions) (transport.Stream, error) {
	sim := d.w.simOf(t.NodeID)
	if d.w.openFail[fmt.Sprintf("%s/%d", sim.label, c.Stream)] {
		return nil, smerr.New(smerr.CodeNodeUnreachable, "", "no session could be opened")
	}
	if c.Stream == templates.StreamImport {
		d.w.clock.Advance(d.w.openDelay)
		d.w.extendLease(ctx)
	}
	return sim.openStream(c)
}

// ---- the world -------------------------------------------------------------------------------------------------

type runOptions struct {
	stateful bool
	compose  string
}

type runWorld struct {
	*moveWorld
	opts     runOptions
	stateful bool
	dialer   runDialer
	handler  appMoveHandler
	a, b     *moveSim
	good     database.Deployment
	lease    jobs.Lease
	mounts   map[string]string // mount target -> volume name

	mu          sync.Mutex
	log         []string
	faults      []streamFault
	seen        map[string]int
	crash       map[string]int // kind -> the tick to stop at
	ticks       map[string]int
	unhealthy   bool
	healthyA    bool // the source answers its health checks even when unhealthy is set
	stuck       bool // sleeping does not move the clock
	before      func(label string, c templates.Command)
	hook        func()          // runs when B's health check is asked
	afterVerify func()          // runs when the export that verifies a volume ends on B
	openDelay   time.Duration   // how long opening an import stream takes
	openFail    map[string]bool // "A/<kind>" or "B/<kind>": opening that kind of stream fails
}

func newRunWorld(t *testing.T, o runOptions) *runWorld {
	t.Helper()
	mw := newMoveWorld(t)
	w := &runWorld{moveWorld: mw, opts: o, stateful: o.stateful, seen: map[string]int{}, crash: map[string]int{}, ticks: map[string]int{}}
	w.dialer = runDialer{fakeDialer: newFakeDialer(t), w: w}
	w.a, w.b = newMoveSim(w, "A", w.node.ID), newMoveSim(w, "B", w.dest.ID)
	for _, id := range []domain.ID{w.node.ID, w.dest.ID} {
		w.inTx(func(ctx context.Context, tx *database.Tx) error {
			err := database.SetNodeCapability(ctx, tx, id, database.NodeCapability{
				Capability: capabilitySetup, Available: true, CheckedAt: w.clock.Now(),
				Metadata: map[string]any{"setup_version": 2, "deploy_root": "/srv/supermgmt"},
			})
			if err != nil {
				return err
			}
			return database.SetNodeCapability(ctx, tx, id, database.NodeCapability{Capability: "health.http", Available: true, CheckedAt: w.clock.Now()})
		})
	}
	w.exec(`UPDATE environments SET config_json = json_set(config_json, '$.allow_automatic_rollback', json('true'))`)
	if o.compose != "" {
		w.editCompose(o.compose)
	}
	w.seedKnownGood()
	c, err := newCore(w.cfg)
	mustf(t, err, "newCore")
	conn := Connector{Remote: w.dialer}
	dep := &deployHandler{
		core: c, store: w.store, secrets: &dhSecrets{}, http: &http.Client{}, dial: conn.Automated, sleep: w.sleep,
	}
	w.handler = appMoveHandler{core: c, dep: dep, conn: conn, checkpoint: func() error { return w.tickError("checkpoint") }}
	return w
}

func (w *runWorld) editCompose(text string) {
	w.t.Helper()
	policy := w.app.ImagePolicy
	policy.Pinned = append(slices.Clone(policy.Pinned), appsRedisPinned)
	policy.Sidecars = map[string]string{"redis": "docker.io/library/redis"}
	_, err := w.apps.Update(context.Background(), w.caller(w.admin), w.app.ID, w.app.SpecRevision,
		wire.AppPatch{ComposeContent: &text, ImagePolicy: &policy})
	mustf(w.t, err, "edit the compose")
}

// seedKnownGood runs a real deployment through finalization and records it as the running, known-good one on A.
func (w *runWorld) seedKnownGood() {
	w.t.Helper()
	first := w.mustFinalize(w.create().ID)
	w.markKnownGood(first.ID)
	w.exec(`UPDATE jobs SET state = 'succeeded' WHERE id = ?`, *first.JobID)
	w.clock.Advance(time.Second)
	w.good = w.row(first.ID)
	w.a.state, w.a.deployment = "running", w.good.ID
}

// started requests, approves and claims the move; the world then runs it with run.
func (w *runWorld) started() {
	w.t.Helper()
	res := w.mustMove()
	for _, v := range res.Volumes {
		w.a.volumes[v.VolumeName] = map[string]string{"seeded-by-image": "1", "a.txt": "alpha", "dir/b.txt": "bravo-" + v.VolumeName}
		if w.mounts == nil {
			w.mounts = map[string]string{}
		}
		w.mounts[v.MountTarget] = v.VolumeName
	}
	w.approved(res)
	claimed, found := w.claim()
	if !found {
		w.t.Fatal("the approved move was not claimed")
	}
	w.lease = claimed.Lease
}

func (w *runWorld) run() error {
	w.t.Helper()
	return w.handler.Run(context.Background(), w.lease)
}

// resume runs the handler again on the same lease, as a retry of the job would after a crash.
func (w *runWorld) resume() error {
	w.t.Helper()
	w.extendLease(context.Background())
	return w.run()
}

func (w *runWorld) extendLease(ctx context.Context) {
	w.t.Helper()
	err := w.db.WithWriteTx(ctx, func(ctx context.Context, tx *database.Tx) error {
		_, err := tx.ExecContext(ctx, `UPDATE jobs SET lease_until = ? WHERE id = ?`, domain.UnixMillis(w.clock.Now().Add(time.Hour)), w.lease.JobID)
		return err
	})
	mustf(w.t, err, "extend the lease")
}

// sleep moves the clock, unless the world is stuck, the way a real wait would.
func (w *runWorld) sleep(ctx context.Context, d time.Duration) {
	if !w.stuck {
		w.clock.Advance(d)
		w.extendLease(ctx)
	}
}

func (w *runWorld) project() string { return w.moveWorld.project() }

func (w *runWorld) volumeNames() []string {
	names := make([]string, 0, len(w.mounts))
	for _, name := range w.mounts {
		names = append(names, name)
	}
	slices.Sort(names)
	return names
}

func (w *runWorld) simOf(id domain.ID) *moveSim {
	if id == w.dest.ID {
		return w.b
	}
	return w.a
}

func (w *runWorld) faultFor(label string, kind templates.StreamKind, mount string) string {
	w.mu.Lock()
	defer w.mu.Unlock()
	key := fmt.Sprintf("%s/%d/%s", label, kind, mount)
	w.seen[key]++
	for _, f := range w.faults {
		if f.label == label && f.kind == kind && f.mount == mount && f.nth == w.seen[key] {
			return f.mode
		}
	}
	return ""
}

func (w *runWorld) fail(label string, kind templates.StreamKind, mount string, nth int, mode string) {
	w.faults = append(w.faults, streamFault{label: label, kind: kind, mount: mount, nth: nth, mode: mode})
}

// tick counts one event of a kind and reports whether it is the one the world was told to stop at.
func (w *runWorld) tick(kind string) bool {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.ticks[kind]++
	return w.crash[kind] != 0 && w.ticks[kind] == w.crash[kind]
}

func (w *runWorld) tickError(kind string) error {
	if w.tick(kind) {
		return fmt.Errorf("%w: crash at a %s", jobs.ErrOutcomeUnknown, kind) // a crash is no failure to settle
	}
	return nil
}

// afterDispatch runs after a mutating command took effect: the node's answer is lost when this is the dispatch the
// world should crash at.
func (w *runWorld) afterDispatch(_ *moveSim, _ templates.Command) error {
	if w.tick("dispatch") {
		return errors.New("connection lost")
	}
	return nil
}

func (w *runWorld) healthAnswer(s *moveSim) string {
	if w.unhealthy && (!w.healthyA || s != w.a) {
		return "500"
	}
	return "200"
}

func (w *runWorld) verifyReply(c templates.Command) (transport.Result, error) {
	match := dhDirectory.FindStringSubmatch(c.Line)
	if match == nil {
		return transport.Result{ExitStatus: 2}, nil
	}
	directory := domain.ID(match[1])
	fz, err := w.handler.dep.freeze(context.Background(), w.planOf(directory).Content)
	mustf(w.t, err, "freeze")
	hashes := compose.ExpectedEnvHashes(fz.frozen, fz.secrets)
	model, err := expectedMaskedModel(fz.frozen, directory, hashes)
	mustf(w.t, err, "expectedMaskedModel")
	out := nodeVerification{Model: model}
	for _, h := range hashes {
		sum := h.SHA256
		out.Set = append(out.Set, nodeEnvHash{Service: h.Service, EnvName: h.EnvName, SHA256: &sum})
	}
	raw, err := json.Marshal(out)
	mustf(w.t, err, "marshal verification")
	return transport.Result{Stdout: raw}, nil
}

// ---- reading the outcome -----------------------------------------------------------------------------------------

func (w *runWorld) moveRow() database.AppMove {
	w.t.Helper()
	all, err := database.ListAppMovesByTarget(context.Background(), w.db.Reader(), w.target.ID)
	mustf(w.t, err, "ListAppMovesByTarget")
	if len(all) != 1 {
		w.t.Fatalf("moves = %d, want 1", len(all))
	}
	return all[0]
}

func (w *runWorld) targetRow() database.AppTarget {
	w.t.Helper()
	row, err := database.GetAppTarget(context.Background(), w.db.Reader(), w.target.ID)
	mustf(w.t, err, "GetAppTarget")
	return row
}

func (w *runWorld) volumeRow(name string) database.AppMoveVolume {
	w.t.Helper()
	v, err := database.GetAppMoveVolume(context.Background(), w.db.Reader(), w.moveRow().ID, name)
	mustf(w.t, err, "GetAppMoveVolume")
	return v
}

func (w *runWorld) logged() []string {
	w.mu.Lock()
	defer w.mu.Unlock()
	return slices.Clone(w.log)
}

// logIndex is the position of the first log line that equals entry at or after from; -1 when there is none.
func logIndex(log []string, entry string, from int) int {
	for i := from; i < len(log); i++ {
		if log[i] == entry {
			return i
		}
	}
	return -1
}

func (w *runWorld) mutations(sim *moveSim) []string {
	sim.node.mu.Lock()
	defer sim.node.mu.Unlock()
	var out []string
	for _, c := range sim.node.calls {
		if c.Mutating {
			out = append(out, c.Template)
		}
	}
	return out
}

// ---- tests -------------------------------------------------------------------------------------------------------

func TestMoveRun_AStatelessAppMovesAndASourceKeepsServingUntilBIsHealthy(t *testing.T) {
	w := newRunWorld(t, runOptions{})
	w.started()

	mustf(t, w.run(), "Run")

	m := w.moveRow()
	if m.Phase != database.AppMoveDone || m.BStartedAt == nil || m.CommittedRevision == 0 || m.DestDeploymentID == nil {
		t.Fatalf("move = %+v, want done, started and committed", m)
	}
	if got := w.targetRow(); got.NodeID != w.dest.ID || got.SpecRevision != m.CommittedRevision {
		t.Errorf("target = %+v, want it on B at the committed revision", got)
	}
	b := w.row(*m.DestDeploymentID)
	if b.Kind != deployments.KindMove || b.State != deployments.StateSucceeded || !b.KnownGood || b.NodeID != w.dest.ID {
		t.Errorf("B's deployment = %+v, want a succeeded known-good move deployment on B", b)
	}
	if newest, err := database.NewestKnownGood(context.Background(), w.db.Reader(), w.target.ID, nil); err != nil || newest.ID != b.ID {
		t.Errorf("newest known good = %v (%v), want B's deployment", newest.ID, err)
	}
	if w.a.state != "exited" || w.b.state != "running" {
		t.Errorf("A is %s and B is %s, want A parked stopped and B running", w.a.state, w.b.state)
	}
	log := w.logged()
	health, stop := logIndex(log, "B health.http", 0), logIndex(log, "A compose.stop", 0)
	if health < 0 || stop < 0 || stop < health {
		t.Errorf("A stopped at %d, B healthy at %d: A must serve until B passed its checks\n%s", stop, health, strings.Join(log, "\n"))
	}
	if volumes := w.exportsAndImports(); len(volumes) != 0 {
		t.Errorf("a stateless move copied data: %v", volumes)
	}
	if got := w.mutations(w.a); !slices.Equal(got, []string{"docker.update_restart", "compose.stop"}) {
		t.Errorf("mutations on A = %v, want the restart hold and the park only", got)
	}
	if got := w.a.restartOf("web"); got != "no" {
		t.Errorf("A's restart policy = %q, want it held at no so the parked source cannot come back", got)
	}
	want := []string{"compose.pull", "compose.materialize", "compose.create", "compose.start"}
	if got := w.mutations(w.b); !slices.Equal(got, want) {
		t.Errorf("mutations on B = %v, want %v", got, want)
	}
	for _, step := range []string{"pull", "materialize", "verify-on-node", "create"} {
		if got := w.stepsOf(b.ID)[step]; got != database.StepSucceeded {
			t.Errorf("step %s is %q", step, got)
		}
	}
	if w.good.ID == b.ID || !w.row(w.good.ID).KnownGood {
		t.Error("the source's deployment must stay as it was")
	}
}

func (w *runWorld) stepsOf(id domain.ID) map[string]database.StepState {
	w.t.Helper()
	rows, err := database.ListDeploymentSteps(context.Background(), w.db.Reader(), id)
	mustf(w.t, err, "ListDeploymentSteps")
	out := map[string]database.StepState{}
	for _, r := range rows {
		out[r.Name] = r.State
	}
	return out
}

func (w *runWorld) exportsAndImports() []string {
	var out []string
	for _, entry := range w.logged() {
		if strings.Contains(entry, " export ") || strings.Contains(entry, " import ") {
			out = append(out, entry)
		}
	}
	return out
}

func TestMoveRun_AStatefulAppCopiesEachVolumeOnceAndAVolumeSharedByTwoServicesIsNotCopiedTwice(t *testing.T) {
	w := newRunWorld(t, runOptions{stateful: true, compose: moveStatefulCompose})
	w.started()
	var seenAtCreate []bool
	w.before = func(label string, c templates.Command) {
		if label != "B" || c.Template != "compose.create" {
			return
		}
		rows, err := database.ListAppMoveVolumes(context.Background(), w.db.Reader(), w.moveRow().ID)
		mustf(t, err, "ListAppMoveVolumes")
		for _, v := range rows {
			seenAtCreate = append(seenAtCreate, v.CreatedByMove)
		}
	}

	mustf(t, w.run(), "Run")

	if m := w.moveRow(); m.Phase != database.AppMoveDone || !m.Stateful {
		t.Fatalf("move = %+v, want a stateful move done", m)
	}
	names := w.volumeNames()
	if len(names) != 2 {
		t.Fatalf("volume map = %v, want data and cache", names)
	}
	for _, name := range names {
		a, _ := w.a.volumeFiles(name)
		b, _ := w.b.volumeFiles(name)
		if !maps_equal(a, b) {
			t.Errorf("volume %s: B holds %v, A holds %v", name, b, a)
		}
		v := w.volumeRow(name)
		if v.State != database.AppMoveVolumeVerified || v.Attempt != 1 || v.SourceDigest == "" || v.SourceDigest != v.DestDigest || !v.CreatedByMove {
			t.Errorf("volume row = %+v, want verified at the first attempt with equal digests", v)
		}
	}
	for _, mount := range []string{"/data", "/var/cache/web"} {
		if got := countOf(w.logged(), "A export "+mount); got != 1 {
			t.Errorf("exports of %s from A = %d, want 1", mount, got)
		}
		if got := countOf(w.logged(), "B import "+mount); got != 1 {
			t.Errorf("imports of %s into B = %d, want 1", mount, got)
		}
		if got := countOf(w.logged(), "B export "+mount); got != 1 {
			t.Errorf("verifying exports of %s from B = %d, want 1", mount, got)
		}
	}
	log := w.logged()
	if stop, first := logIndex(log, "A compose.stop", 0), firstWith(log, "A export"); stop < 0 || first < stop {
		t.Errorf("A stopped at %d, first export at %d: A must have stopped first\n%s", stop, first, strings.Join(log, "\n"))
	}
	if len(seenAtCreate) == 0 || slices.Contains(seenAtCreate, false) {
		t.Errorf("created_by_move at compose.create = %v, want every volume marked before the dispatch", seenAtCreate)
	}
	if w.a.state != "exited" || w.b.state != "running" {
		t.Errorf("A is %s and B is %s", w.a.state, w.b.state)
	}
	for _, name := range names {
		if _, present := w.a.volumeFiles(name); !present {
			t.Errorf("A's volume %s is gone", name)
		}
	}
	w.wantIntent("docker.volume_import", 2)
	w.wantIntent("compose.create", 1)
	w.wantIntent("compose.start", 1)
	w.wantIntent("compose.stop", 1)
	for _, in := range w.intentsOf("docker.volume_import") {
		if in.DeadlineAt.Sub(*in.DispatchedAt) < templates.KillAfter+10*time.Minute {
			t.Errorf("import intent deadline %s after dispatch, want the copy's deadline plus the kill margin", in.DeadlineAt.Sub(*in.DispatchedAt))
		}
		if in.Outcome != jobs.OutcomeSucceeded {
			t.Errorf("import intent outcome = %q", in.Outcome)
		}
	}
}

func maps_equal(a, b map[string]string) bool {
	return len(a) == len(b) && func() bool {
		for k, v := range a {
			if b[k] != v {
				return false
			}
		}
		return true
	}()
}

func countOf(log []string, entry string) int {
	n := 0
	for _, l := range log {
		if l == entry {
			n++
		}
	}
	return n
}

func firstWith(log []string, prefix string) int {
	for i, l := range log {
		if strings.HasPrefix(l, prefix) {
			return i
		}
	}
	return -1
}

func (w *runWorld) intentsOf(operation string) []jobs.Intent {
	w.t.Helper()
	all, err := w.store.Intents(context.Background(), w.db.Reader(), w.lease.JobID)
	mustf(w.t, err, "Intents")
	return slices.DeleteFunc(all, func(i jobs.Intent) bool { return i.Operation != operation })
}

func (w *runWorld) wantIntent(operation string, n int) {
	w.t.Helper()
	if got := len(w.intentsOf(operation)); got != n {
		w.t.Errorf("intents for %s = %d, want %d", operation, got, n)
	}
}

// ---- preflight ---------------------------------------------------------------------------------------------------

func TestMoveRun_PreflightRefusesAnUnfitDestinationWithOnlyReadsOnBothNodes(t *testing.T) {
	tests := []struct {
		name   string
		opts   runOptions
		unfit  func(w *runWorld)
		reason string
	}{
		{"an image with no variant for the platform", runOptions{}, func(w *runWorld) { w.b.noPlatform = true }, causeMovePlatform},
		{"memory below the services' limits", runOptions{compose: moveLimitedCompose}, func(w *runWorld) { w.b.memTotal = 256 << 20 }, causeMoveMemoryLow},
		{
			"disk below the images, the volumes and the margin",
			runOptions{stateful: true, compose: moveStatefulCompose},
			func(w *runWorld) { w.b.free = preflightHeadroom + 1<<20 }, causePreflightDiskLow,
		},
		{
			"a volume of the target already on B",
			runOptions{stateful: true, compose: moveStatefulCompose},
			func(w *runWorld) { w.b.volumes[w.volumeNames()[0]] = map[string]string{"x": "y"} }, causeMoveVolumeExists,
		},
		{"a source that runs another deployment", runOptions{}, func(w *runWorld) { w.a.deployment = "00000000-0000-0000-0000-000000000000" }, causeMoveSourceNotRunning},
		{
			"a source without one of the volumes",
			runOptions{stateful: true, compose: moveStatefulCompose},
			func(w *runWorld) { delete(w.a.volumes, w.volumeNames()[0]) }, causeMoveVolumeMissing,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			w := newRunWorld(t, tc.opts)
			w.started()
			tc.unfit(w)

			err := w.run()

			if appsReasonOf(err) != smerr.ReasonPreflightFailed {
				t.Fatalf("Run = %v, want PREFLIGHT_FAILED", err)
			}
			var typed *smerr.Error
			if !errors.As(err, &typed) || typed.Details["cause"] != tc.reason {
				t.Errorf("error = %+v, want cause %s", typed, tc.reason)
			}
			if got := append(w.mutations(w.a), w.mutations(w.b)...); len(got) != 0 {
				t.Errorf("a refused preflight ran mutating commands: %v", got)
			}
			if w.a.state != "running" || w.moveRow().Phase != database.AppMoveRolledBack || w.moveRow().DestDeploymentID != nil {
				t.Errorf("A is %s, move %+v: nothing may have changed and the move is rolled back", w.a.state, w.moveRow())
			}
		})
	}
}

func TestMoveRun_TheAdmissionChecksRunAgainUnderTheLocksBeforeStagingAndBeforeStarting(t *testing.T) {
	disable := func(w *runWorld) {
		w.inTx(func(ctx context.Context, tx *database.Tx) error {
			return database.SetNodeCapability(ctx, tx, w.dest.ID, database.NodeCapability{
				Capability: capabilityComposeDeploy, Available: false, CheckedAt: w.clock.Now(),
			})
		})
	}
	t.Run("before staged", func(t *testing.T) {
		w := newRunWorld(t, runOptions{})
		w.started()
		disable(w)

		err := w.run()

		wantAppsCode(t, err, smerr.CodeCapabilityUnavailable)
		if got := append(w.mutations(w.a), w.mutations(w.b)...); len(got) != 0 || w.moveRow().Phase != database.AppMoveRolledBack {
			t.Errorf("mutations = %v, phase %s: a failed re-check stages nothing and rolls the move back", got, w.moveRow().Phase)
		}
	})
	t.Run("before started", func(t *testing.T) {
		w := newRunWorld(t, runOptions{})
		w.started()
		w.before = func(label string, c templates.Command) {
			if label == "B" && c.Template == "compose.create" {
				disable(w)
			}
		}

		err := w.run()

		wantAppsCode(t, err, smerr.CodeCapabilityUnavailable)
		if m := w.moveRow(); m.Phase != database.AppMoveRolledBack || m.BStartedAt != nil {
			t.Errorf("move = %+v, want rolled back and never started", m)
		}
		if w.a.state != "running" || len(w.mutations(w.a)) != 0 || slices.Contains(w.mutations(w.b), "compose.start") {
			t.Errorf("A is %s, A mutations %v, B mutations %v: A must keep serving and B must not start", w.a.state, w.mutations(w.a), w.mutations(w.b))
		}
	})
	t.Run("another open work for the target", func(t *testing.T) {
		w := newRunWorld(t, runOptions{})
		w.started()
		w.exec(`UPDATE deployments SET state = 'queued' WHERE id = ?`, w.good.ID) // work that opened after the plan

		err := w.run()

		wantAppsCode(t, err, smerr.CodeConflict)
		if !strings.Contains(err.Error(), w.good.ID.String()) {
			t.Errorf("error = %v, want it to name the open deployment", err)
		}
	})
}

// ---- failed copies are replaced ------------------------------------------------------------------------------------

func TestMoveRun_AFailedImportIsReplacedNeverMerged(t *testing.T) {
	w := newRunWorld(t, runOptions{stateful: true, compose: moveStatefulCompose})
	w.started()
	w.fail("B", templates.StreamImport, "/data", 1, "exit1")

	mustf(t, w.run(), "Run")

	data := w.mounts["/data"]
	if v := w.volumeRow(data); v.State != database.AppMoveVolumeVerified || v.Attempt != 2 {
		t.Errorf("volume = %+v, want verified at the second attempt", v)
	}
	log := w.logged()
	failed := logIndex(log, "B import /data", 0)
	down, rm, create := logIndex(log, "B compose.down", failed), logIndex(log, "B docker.volume_rm", failed), logIndex(log, "B compose.create", failed)
	second := logIndex(log, "B import /data", failed+1)
	if failed < 0 || failed >= down || down >= rm || rm >= create || create >= second {
		t.Errorf("order: import %d, down %d, volume rm %d, create %d, import again %d\n%s", failed, down, rm, create, second, strings.Join(log, "\n"))
	}
	a, _ := w.a.volumeFiles(data)
	if b, _ := w.b.volumeFiles(data); !maps_equal(a, b) {
		t.Errorf("B holds %v, want exactly A's %v", b, a)
	}
	if got := w.b.imports[data]; got != 1 {
		t.Errorf("imports applied to the volume = %d, want 1", got)
	}
}

func TestMoveRun_AnExportThatFailsLeavesTheImportUnprovenUntilItsDeadlineThenReplacesTheVolume(t *testing.T) {
	w := newRunWorld(t, runOptions{stateful: true, compose: moveStatefulCompose})
	w.started()
	w.fail("A", templates.StreamExport, "/data", 1, "exit1")
	start := w.clock.Now()

	mustf(t, w.run(), "Run")

	if v := w.volumeRow(w.mounts["/data"]); v.State != database.AppMoveVolumeVerified || v.Attempt != 2 {
		t.Errorf("volume = %+v, want verified at the second attempt", v)
	}
	if waited := w.clock.Now().Sub(start); waited < 10*time.Minute+templates.KillAfter {
		t.Errorf("the run waited %s, want the import's deadline plus the kill margin", waited)
	}
}

func TestMoveRun_AManifestMismatchReplacesTheVolume(t *testing.T) {
	w := newRunWorld(t, runOptions{stateful: true, compose: moveStatefulCompose})
	w.started()
	w.fail("B", templates.StreamImport, "/data", 1, "corrupt")

	mustf(t, w.run(), "Run")

	data := w.mounts["/data"]
	if v := w.volumeRow(data); v.State != database.AppMoveVolumeVerified || v.Attempt != 2 {
		t.Errorf("volume = %+v, want verified at the second attempt", v)
	}
	a, _ := w.a.volumeFiles(data)
	if b, _ := w.b.volumeFiles(data); !maps_equal(a, b) {
		t.Errorf("B holds %v, want exactly A's %v", b, a)
	}
	log := w.logged()
	if logIndex(log, "B docker.volume_rm", 0) < 0 || countOf(log, "B import /data") != 2 {
		t.Errorf("log = %v, want the volume removed and imported twice", log)
	}
}

func TestMoveRun_ACopyThatKeepsFailingEndsTheMoveAfterItsAttempts(t *testing.T) {
	w := newRunWorld(t, runOptions{stateful: true, compose: moveStatefulCompose})
	w.started()
	for nth := 1; nth <= moveCopyAttempts; nth++ {
		w.fail("B", templates.StreamImport, "/data", nth, "exit1")
	}

	err := w.run()

	wantAppsCode(t, err, smerr.CodeDeploymentFailed)
	if v := w.volumeRow(w.mounts["/data"]); v.Attempt != moveCopyAttempts || v.State != database.AppMoveVolumeImporting {
		t.Errorf("volume = %+v, want the last attempt left as it failed", v)
	}
	if got := countOf(w.logged(), "B import /data"); got != moveCopyAttempts {
		t.Errorf("imports = %d, want %d", got, moveCopyAttempts)
	}
}

func TestMoveRun_AnImportWithAnUnknownOutcomeIsNotTouchedBeforeItsDeadline(t *testing.T) {
	w := newRunWorld(t, runOptions{stateful: true, compose: moveStatefulCompose})
	w.started()
	w.fail("B", templates.StreamImport, "/data", 1, "lost")
	w.stuck = true
	data := w.mounts["/data"]

	err := w.run()

	if !errors.Is(err, jobs.ErrOutcomeUnknown) {
		t.Fatalf("Run = %v, want an unknown outcome", err)
	}
	v := w.volumeRow(data)
	if v.State != database.AppMoveVolumeImporting || v.ImportDeadlineAt == nil || !v.ImportDeadlineAt.After(w.clock.Now()) {
		t.Fatalf("volume = %+v, want importing with a deadline still ahead", v)
	}
	before := slices.Clone(w.mutations(w.b))
	if err := w.resume(); !errors.Is(err, jobs.ErrOutcomeUnknown) {
		t.Fatalf("second Run = %v, want the outcome to stay unknown", err)
	}
	if got := w.mutations(w.b); !slices.Equal(got, before) {
		t.Errorf("B mutations went from %v to %v before the deadline: the volume must stay untouched", before, got)
	}
	if got := countOf(w.logged(), "B import /data"); got != 1 {
		t.Errorf("imports = %d before the deadline, want the one in doubt", got)
	}

	w.stuck = false
	mustf(t, w.resume(), "Run after the deadline")

	if v := w.volumeRow(data); v.State != database.AppMoveVolumeVerified || v.Attempt != 2 {
		t.Errorf("volume = %+v, want replaced and verified at the second attempt", v)
	}
	if w.clock.Now().Before(*v.ImportDeadlineAt) {
		t.Error("the volume was replaced before the deadline passed")
	}
	a, _ := w.a.volumeFiles(data)
	if b, _ := w.b.volumeFiles(data); !maps_equal(a, b) {
		t.Errorf("B holds %v, want exactly A's %v", b, a)
	}
}

// ---- start, verify, commit and park ----------------------------------------------------------------------------------

func TestMoveRun_AnUnhealthyBEndsTheMoveBeforeTheCommit(t *testing.T) {
	w := newRunWorld(t, runOptions{})
	w.started()
	w.unhealthy, w.healthyA = true, true

	err := w.run()

	if appsReasonOf(err) != smerr.ReasonHealthFailed {
		t.Fatalf("Run = %v, want HEALTH_FAILED", err)
	}
	if m := w.moveRow(); m.Phase != database.AppMoveRolledBack || m.BStartedAt == nil {
		t.Errorf("move = %+v, want rolled back after B started", m)
	}
	if w.targetRow().NodeID != w.node.ID || w.a.state != "running" || w.b.state != "exited" {
		t.Errorf("target on %s, A %s, B %s: nothing is committed, A serves and B is stopped", w.targetRow().NodeID, w.a.state, w.b.state)
	}
}

func TestMoveRun_ACommitThatLosesItsCompareAndSetGoesToCompensationNotForward(t *testing.T) {
	w := newRunWorld(t, runOptions{})
	w.started()
	bumped := false
	w.beforeHealth(func() {
		if !bumped {
			bumped = true
			w.exec(`UPDATE app_targets SET spec_revision = spec_revision + 1 WHERE id = ?`, w.target.ID)
		}
	})

	err := w.run()

	wantAppsCode(t, err, smerr.CodeConflict)
	m := w.moveRow()
	if m.Phase != database.AppMoveRolledBack || m.CommittedRevision != 0 {
		t.Errorf("move = %+v, want rolled back and uncommitted", m)
	}
	if got := w.targetRow(); got.NodeID != w.node.ID {
		t.Errorf("target on %s, want it left on A", got.NodeID)
	}
	if row := w.row(*m.DestDeploymentID); row.State != deployments.StateFailed || row.KnownGood {
		t.Errorf("B's deployment = %+v, want it failed and not known good", row)
	}
}

func (w *runWorld) beforeHealth(f func()) {
	w.hook = f
}

func TestMoveRun_ACrashAfterTheCommitResumesToDone(t *testing.T) {
	w := newRunWorld(t, runOptions{})
	w.started()
	w.crash["dispatch"] = 5 // pull, materialize, create, start, then the park of A

	err := w.run()

	if !errors.Is(err, jobs.ErrOutcomeUnknown) {
		t.Fatalf("Run = %v, want an unknown outcome", err)
	}
	m := w.moveRow()
	if m.Phase != database.AppMoveCommitted || w.targetRow().NodeID != w.dest.ID {
		t.Fatalf("move %s, target on %s: want it committed", m.Phase, w.targetRow().NodeID)
	}
	w.crash["dispatch"] = 0

	mustf(t, w.resume(), "Run after the crash")

	if got := w.moveRow(); got.Phase != database.AppMoveDone || got.CommittedRevision != m.CommittedRevision {
		t.Errorf("move = %+v, want done at the revision the commit wrote", got)
	}
	if got := countOf(w.logged(), "B compose.start"); got != 1 {
		t.Errorf("B was started %d times, want 1", got)
	}
}

func TestMoveRun_AFailureAfterTheCommitHaltsOnTheLastAttemptAndNeverCompensates(t *testing.T) {
	w := newRunWorld(t, runOptions{})
	w.started()
	w.exec(`UPDATE jobs SET attempts = max_attempts WHERE id = ?`, w.lease.JobID)
	w.a.node.exit("compose.stop", 1)

	err := w.run()

	wantAppsCode(t, err, smerr.CodeDeploymentFailed)
	m := w.moveRow()
	if m.Phase != database.AppMoveFailed || m.HaltedPhase != database.AppMoveCommitted || m.LastError == "" {
		t.Errorf("move = %+v, want halted in committed", m)
	}
	if w.targetRow().NodeID != w.dest.ID || w.b.state != "running" {
		t.Errorf("target on %s, B %s: the committed move is never undone", w.targetRow().NodeID, w.b.state)
	}
}

func TestMoveRun_TheCopyTakesNoActionUnlessTheLeaseIsStillTheJobs(t *testing.T) {
	w := newRunWorld(t, runOptions{stateful: true, compose: moveStatefulCompose})
	w.started()
	w.exec(`UPDATE jobs SET lease_generation = lease_generation + 1 WHERE id = ?`, w.lease.JobID)

	err := w.run()

	if !errors.Is(err, jobs.ErrLeaseLost) {
		t.Fatalf("Run = %v, want the lost lease", err)
	}
	if got := append(w.mutations(w.a), w.mutations(w.b)...); len(got) != 0 {
		t.Errorf("a run without its lease changed a node: %v", got)
	}
}

// ---- crash injection ---------------------------------------------------------------------------------------------

func TestMoveRun_ACrashAtAnyDispatchOrCheckpointResumesWithoutCopyingAVerifiedVolumeAgain(t *testing.T) {
	dry := newRunWorld(t, runOptions{stateful: true, compose: moveStatefulCompose})
	dry.started()
	mustf(t, dry.run(), "uninterrupted Run")
	total := map[string]int{"dispatch": dry.ticks["dispatch"], "checkpoint": dry.ticks["checkpoint"]}
	if total["dispatch"] < 7 || total["checkpoint"] < 10 {
		t.Fatalf("ticks = %v: the run has too few dispatches or checkpoints to test", total)
	}

	for _, kind := range []string{"dispatch", "checkpoint"} {
		for n := 1; n <= total[kind]; n++ {
			t.Run(fmt.Sprintf("%s %d", kind, n), func(t *testing.T) {
				w := newRunWorld(t, runOptions{stateful: true, compose: moveStatefulCompose})
				w.started()
				w.crash[kind] = n

				if err := w.run(); err == nil {
					t.Fatal("the crash did not stop the run")
				}
				verified := map[string]int{}
				for _, name := range w.volumeNames() {
					if w.volumeRow(name).State == database.AppMoveVolumeVerified {
						verified[name] = w.b.imports[name]
					}
				}
				w.crash[kind], w.stuck = 0, false

				mustf(t, w.resume(), "resumed Run")

				if m := w.moveRow(); m.Phase != database.AppMoveDone {
					t.Fatalf("move = %+v, want done", m)
				}
				for name, imported := range verified {
					if got := w.b.imports[name]; got != imported {
						t.Errorf("volume %s was verified before the crash and imported %d more time(s) after it", name, got-imported)
					}
				}
				for _, name := range w.volumeNames() {
					a, _ := w.a.volumeFiles(name)
					if b, _ := w.b.volumeFiles(name); !maps_equal(a, b) {
						t.Errorf("volume %s: B holds %v, A holds %v", name, b, a)
					}
				}
				if got := w.targetRow(); got.NodeID != w.dest.ID {
					t.Errorf("target on %s, want B", got.NodeID)
				}
			})
		}
	}
}

// ---- target edits ------------------------------------------------------------------------------------------------

func TestMoveRun_APolicyEditOfATargetWithAnOpenMoveIsRefusedAtRequestAndAtApply(t *testing.T) {
	w := newMoveWorld(t)
	w.seedGood(goodModel{})
	w.mustMove()
	target := w.targetRow()

	_, err := w.apps.UpdateTarget(context.Background(), w.caller(w.admin), target.ID, target.SpecRevision, wire.AppTargetPatch{DeploymentPolicy: &wire.DeploymentPolicy{}})
	wantRefusal(t, err, smerr.CodeConflict, "move")

	w.inTx(func(ctx context.Context, tx *database.Tx) error {
		_, err := w.apps.applyUpdateTarget(ctx, tx, domain.Actor{ID: w.admin, Type: domain.ActorHuman}, appTargetUpdateParams{
			TargetID: target.ID, ExpectedRevision: target.SpecRevision, Policy: wire.DeploymentPolicy{},
		})
		wantRefusal(t, err, smerr.CodeConflict, "move")
		return nil
	})
}

func (w *moveWorld) targetRow() database.AppTarget {
	w.t.Helper()
	row, err := database.GetAppTarget(context.Background(), w.db.Reader(), w.target.ID)
	mustf(w.t, err, "GetAppTarget")
	return row
}

// ---- limits ------------------------------------------------------------------------------------------------------

func TestResourceLimits(t *testing.T) {
	tests := []struct {
		name       string
		model      string
		wantMemory int64
		wantCPUs   float64
		wantErr    bool
	}{
		{"no limits", `{"services":{"web":{"image":"x"}}}`, 0, 0, false},
		{"bytes as a number", `{"services":{"web":{"mem_limit":536870912}}}`, 512 << 20, 0, false},
		{"bytes as a string", `{"services":{"web":{"mem_limit":"536870912","cpus":0.5}}}`, 512 << 20, 0.5, false},
		{"a unit", `{"services":{"web":{"mem_limit":"512m"},"db":{"deploy":{"resources":{"limits":{"memory":"1g","cpus":"2"}}}}}}`, 1536 << 20, 2, false},
		{"one limit spelled twice counts once", `{"services":{"web":{"mem_limit":"1g","deploy":{"resources":{"limits":{"memory":"1g"}}}}}}`, 1 << 30, 0, false},
		{"not a size", `{"services":{"web":{"mem_limit":"lots"}}}`, 0, 0, true},
		{"negative", `{"services":{"web":{"mem_limit":-1}}}`, 0, 0, true},
		{"overflowing", `{"services":{"web":{"mem_limit":"9999999999999999999g"}}}`, 0, 0, true},
		{"not a cpu count", `{"services":{"web":{"cpus":"many"}}}`, 0, 0, true},
		{"not json", `[`, 0, 0, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			memory, cpus, err := resourceLimits(json.RawMessage(tc.model))
			if (err != nil) != tc.wantErr || memory != tc.wantMemory || cpus != tc.wantCPUs {
				t.Errorf("resourceLimits = %d, %g, %v; want %d, %g, error %v", memory, cpus, err, tc.wantMemory, tc.wantCPUs, tc.wantErr)
			}
		})
	}
}

// ---- the fixes of review round 1 -----------------------------------------------------------------------------------

func TestMoveRun_TheRecordedImportDeadlineCoversTheTimeOpeningTheStreamTook(t *testing.T) {
	w := newRunWorld(t, runOptions{stateful: true, compose: moveStatefulCompose})
	w.started()
	w.fail("B", templates.StreamImport, "/data", 1, "lost")
	w.stuck = true
	w.openDelay = 30 * time.Second

	err := w.run()

	if !errors.Is(err, jobs.ErrOutcomeUnknown) {
		t.Fatalf("Run = %v, want an unknown outcome", err)
	}
	timeout, _ := copyBounds(1 << 20)
	opened := w.clock.Now() // the clock moved only while the stream opened
	v := w.volumeRow(w.mounts["/data"])
	if v.ImportDeadlineAt == nil || v.ImportDeadlineAt.Before(opened.Add(timeout+templates.KillAfter)) {
		t.Errorf("import deadline %v is before the node-side timeout can end: opened %v + %s + %s", v.ImportDeadlineAt, opened, timeout, templates.KillAfter)
	}
}

func TestMoveRun_AnExportThatCannotOpenRecordsNoImportAndWaitsForNone(t *testing.T) {
	w := newRunWorld(t, runOptions{stateful: true, compose: moveStatefulCompose})
	w.started()
	w.openFail = map[string]bool{fmt.Sprintf("A/%d", templates.StreamExport): true}
	start := w.clock.Now()

	err := w.run()

	if err == nil {
		t.Fatal("Run succeeded")
	}
	if got := countOf(w.logged(), "B import /data"); got != 0 {
		t.Errorf("imports opened = %d, want none: the export failed first", got)
	}
	if v := w.volumeRow(w.mounts["/data"]); v.State != database.AppMoveVolumePending || v.ImportDeadlineAt != nil {
		t.Errorf("volume = %+v, want pending with no import in doubt", v)
	}
	if waited := w.clock.Now().Sub(start); waited >= 10*time.Minute {
		t.Errorf("the run waited %s for an import that never started", waited)
	}
	if m := w.moveRow(); m.Phase != database.AppMoveRolledBack {
		t.Errorf("move = %+v, want rolled back", m)
	}
}

func TestMoveRun_AnUnreadableVerificationExportReplacesTheVolumeInsteadOfEndingTheMove(t *testing.T) {
	w := newRunWorld(t, runOptions{stateful: true, compose: moveStatefulCompose})
	w.started()
	w.fail("B", templates.StreamExport, "/data", 1, "garbage")

	mustf(t, w.run(), "Run")

	data := w.mounts["/data"]
	if v := w.volumeRow(data); v.State != database.AppMoveVolumeVerified || v.Attempt != 2 {
		t.Errorf("volume = %+v, want verified at the second attempt", v)
	}
	a, _ := w.a.volumeFiles(data)
	if b, _ := w.b.volumeFiles(data); !maps_equal(a, b) {
		t.Errorf("B holds %v, want exactly A's %v", b, a)
	}
}

func TestMoveRun_AVolumeThatBearsNoOwnerLabelIsNeverRemovedOnReplacement(t *testing.T) {
	w := newRunWorld(t, runOptions{stateful: true, compose: moveStatefulCompose})
	w.started()
	data := w.mounts["/data"]
	w.b.foreign[data] = true
	w.fail("B", templates.StreamImport, "/data", 1, "exit1")

	err := w.run()

	wantAppsCode(t, err, smerr.CodeConflict)
	if _, present := w.b.volumeFiles(data); !present {
		t.Error("the foreign volume is gone from B")
	}
}

const moveRestartCompose = `
services:
  web:
    image: ghcr.io/acme/web:placeholder
    restart: always
    environment:
      DATABASE_URL: ${secret:db}
    ports:
      - {target: 8080, published: 8080, host_ip: 127.0.0.1}
    volumes:
      - {type: volume, source: data, target: /data}
  redis:
    image: docker.io/library/redis@sha256:3333333333333333333333333333333333333333333333333333333333333333
    restart: unless-stopped
    volumes:
      - {type: volume, source: data, target: /data, read_only: true}
volumes:
  data: {}
`

func TestMoveRun_AStoppedSourceIsHeldAtNoRestartAndGetsItsFrozenPolicyBackOnRollback(t *testing.T) {
	w := newRunWorld(t, runOptions{stateful: true, compose: moveRestartCompose})
	w.started()
	w.unhealthy = true

	if err := w.run(); err == nil {
		t.Fatal("Run succeeded")
	}

	log := w.logged()
	held, stop := logIndex(log, "A restart no", 0), logIndex(log, "A compose.stop", 0)
	if held < 0 || stop < 0 || held > stop {
		t.Errorf("hold at %d, stop at %d: A must be held at no restart before it is stopped\n%s", held, stop, strings.Join(log, "\n"))
	}
	if got := [2]string{w.a.restartOf("web"), w.a.restartOf("redis")}; got != [2]string{"always", "unless-stopped"} {
		t.Errorf("A's restart policies after the rollback = %v, want the frozen ones", got)
	}
	if got := w.b.restartOf("web"); got != "no" {
		t.Errorf("B's restart policy = %q, want a stopped B held at no", got)
	}
	w.wantSourceRunning()
}

func TestMoveRun_ASourceThatCameBackBeforeBStartsOrBeforeTheCommitEndsTheMoveInsteadOfCommitting(t *testing.T) {
	t.Run("before B starts", func(t *testing.T) {
		w := newRunWorld(t, runOptions{stateful: true, compose: moveStatefulCompose})
		w.started()
		w.afterVerify = func() { w.a.mu.Lock(); w.a.state = "running"; w.a.mu.Unlock() }

		if err := w.run(); err == nil {
			t.Fatal("Run succeeded")
		}

		if slices.Contains(w.mutations(w.b), "compose.start") {
			t.Error("B was started next to a running A")
		}
		if m := w.moveRow(); m.Phase != database.AppMoveRolledBack {
			t.Errorf("move = %+v, want rolled back", m)
		}
	})
	t.Run("before the commit", func(t *testing.T) {
		w := newRunWorld(t, runOptions{stateful: true, compose: moveStatefulCompose})
		w.started()
		once := false
		w.hook = func() {
			if !once {
				once = true
				w.a.mu.Lock()
				w.a.state = "running"
				w.a.mu.Unlock()
			}
		}

		if err := w.run(); err == nil {
			t.Fatal("Run succeeded")
		}

		if m := w.moveRow(); m.Phase != database.AppMoveRolledBack || m.CommittedRevision != 0 {
			t.Errorf("move = %+v, want rolled back and never committed", m)
		}
		if got := w.targetRow().NodeID; got != w.node.ID {
			t.Errorf("target on %s, want it left on A", got)
		}
	})
}
