//go:build fixturegen && fixtures

// Command gen produces the migration fixtures of ADR-0035: for each milestone M1..M5 it builds the
// real `sm` of the milestone's merge commit on main (git archive, synthetic version), drives it
// through the scripted world and keeps the database, the master key and a backup archive, with a
// PROVENANCE.md section. Run it with:
//
//	go run -tags fixturegen,fixtures ./test/fixtures/migrations/gen [-only m1,m2] [-ref main]
//
// It needs docker (the node fixture) and the full git history.
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
)

const (
	versionPackage = "github.com/autarquico/supermgmt/internal/version"
	// archiveStamp is the fixed timestamp of the archive name, so a fixture path never moves.
	archiveStamp = "20260101T000000Z"
	archiveExt   = ".tar.zst"
)

type options struct {
	repo, out, ref string
	only           map[string]bool
}

func main() { os.Exit(runMain(os.Args[1:])) }

func runMain(args []string) int {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	o, err := parseOptions(args)
	if err == nil {
		err = generate(ctx, o)
	}
	if err != nil {
		_, _ = fmt.Fprintln(os.Stderr, "gen:", err)
		return 1
	}
	return 0
}

func parseOptions(args []string) (options, error) {
	fs := flag.NewFlagSet("gen", flag.ContinueOnError)
	var o options
	var only string
	fs.StringVar(&o.repo, "repo", ".", "the repository whose history holds the milestone commits (full history)")
	fs.StringVar(&o.out, "out", "", "fixtures directory (default <repo>/test/fixtures/migrations)")
	fs.StringVar(&o.ref, "ref", "main", "the ref every milestone commit must be an ancestor of")
	fs.StringVar(&only, "only", "", "comma-separated milestones to generate (default all)")
	if err := fs.Parse(args); err != nil {
		return o, err
	}
	if o.out == "" {
		o.out = filepath.Join(o.repo, "test", "fixtures", "migrations")
	}
	o.only = map[string]bool{}
	for _, name := range strings.FieldsFunc(only, func(r rune) bool { return r == ',' }) {
		if !knownMilestone(name) {
			return o, fmt.Errorf("-only: unknown milestone %q", name)
		}
		o.only[name] = true
	}
	return o, nil
}

func knownMilestone(name string) bool {
	for _, m := range milestones {
		if m.name == name {
			return true
		}
	}
	return false
}

func (o options) selected(m milestone) bool { return len(o.only) == 0 || o.only[m.name] }

func generate(ctx context.Context, o options) error {
	for _, m := range milestones {
		if !o.selected(m) {
			continue
		}
		if err := requireMergedCommit(ctx, o.repo, o.ref, m.commit); err != nil {
			return fmt.Errorf("%s: %w", m.name, err)
		}
	}
	var records []record
	for _, m := range milestones {
		if !o.selected(m) {
			continue
		}
		r, err := generateMilestone(ctx, o, m)
		if err != nil {
			return fmt.Errorf("%s: %w", m.name, err)
		}
		_, _ = fmt.Fprintf(os.Stdout, "%s: %d files\n", m.name, len(r.files))
		records = append(records, r)
	}
	return writeProvenance(o.out, records)
}

func writeProvenance(out string, records []record) error {
	path := filepath.Join(out, "PROVENANCE.md")
	existing, err := os.ReadFile(path)
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	return os.WriteFile(path, []byte(mergeProvenance(string(existing), records)), 0o644)
}

// generateMilestone builds the milestone's binary, runs its world and stores the fixtures.
func generateMilestone(ctx context.Context, o options, m milestone) (record, error) {
	work, err := os.MkdirTemp("", "smgsrc")
	if err != nil {
		return record{}, err
	}
	defer func() { _ = os.RemoveAll(work) }()
	bin, goVersion, err := buildMilestone(ctx, o.repo, m, work)
	if err != nil {
		return record{}, err
	}
	in, err := newInstallation(ctx, m, bin)
	if err != nil {
		return record{}, err
	}
	defer in.close()
	w := &world{in: in}
	defer w.cleanup(ctx)
	if err := in.start(ctx); err != nil {
		return record{}, err
	}
	if err := w.run(ctx); err != nil {
		return record{}, err
	}
	if err := in.stop(); err != nil {
		return record{}, err
	}
	return collect(ctx, o.out, w, goVersion)
}

// buildMilestone exports the commit with git archive (the working tree is untouched) and builds
// ./cmd/sm for the host as the milestone's synthetic version.
func buildMilestone(ctx context.Context, repo string, m milestone, work string) (bin, goVersion string, err error) {
	src := filepath.Join(work, "src")
	if err := os.MkdirAll(src, 0o755); err != nil {
		return "", "", err
	}
	tarball := filepath.Join(work, "src.tar")
	if err := run(ctx, "git", "-C", repo, "archive", "--format=tar", "--output", tarball, m.commit); err != nil {
		return "", "", err
	}
	if err := run(ctx, "tar", "-xf", tarball, "-C", src); err != nil {
		return "", "", err
	}
	bin = filepath.Join(work, "sm-"+m.name)
	build := exec.CommandContext(ctx, "go", "build", "-trimpath", "-ldflags", "-X "+versionPackage+".Version="+m.version, "-o", bin, "./cmd/sm")
	build.Dir, build.Env = src, append(os.Environ(), "CGO_ENABLED=0")
	if out, err := build.CombinedOutput(); err != nil {
		return "", "", fmt.Errorf("go build %s: %w\n%s", m.commit, err, out)
	}
	version := exec.CommandContext(ctx, "go", "env", "GOVERSION")
	version.Dir = src
	raw, err := version.Output()
	return bin, strings.TrimSpace(string(raw)), err
}

func run(ctx context.Context, name string, args ...string) error {
	if out, err := exec.CommandContext(ctx, name, args...).CombinedOutput(); err != nil {
		return fmt.Errorf("%s %s: %w\n%s", name, strings.Join(args, " "), err, out)
	}
	return nil
}

// collect copies the generated files into <out>/<milestone>/ and hashes them.
func collect(ctx context.Context, out string, w *world, goVersion string) (record, error) {
	m, in := w.in.m, w.in
	schema, err := checkpointedSchemaVersion(ctx, in.databasePath())
	if err != nil {
		return record{}, err
	}
	if schema != m.schema {
		return record{}, fmt.Errorf("the database is at schema %d, the milestone table says %d", schema, m.schema)
	}
	dir := filepath.Join(out, m.name)
	if err := os.RemoveAll(dir); err != nil {
		return record{}, err
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return record{}, err
	}
	kekID, err := copyKey(in.keysDir, filepath.Join(dir, "master.key"))
	if err != nil {
		return record{}, err
	}
	if err := copyFile(in.databasePath(), filepath.Join(dir, "sm.db"), 0o644); err != nil {
		return record{}, err
	}
	rels := []string{"sm.db", "master.key"}
	if m.number() >= 2 {
		name := "supermgmt-" + m.name + "-" + archiveStamp + archiveExt
		if err := copyOnlyArchive(in.backups, filepath.Join(dir, name)); err != nil {
			return record{}, err
		}
		rels = append(rels, name)
	}
	r := record{milestone: m, goVersion: goVersion, schema: schema, kekID: kekID, transcript: w.transcript}
	for _, rel := range rels {
		h, err := hashFile(out, filepath.Join(m.name, rel))
		if err != nil {
			return record{}, err
		}
		r.files = append(r.files, h)
	}
	return r, nil
}

// copyKey copies the one master key file of keysDir and returns its id.
func copyKey(keysDir, dst string) (string, error) {
	keys, err := filepath.Glob(filepath.Join(keysDir, "*.key"))
	if err != nil {
		return "", err
	}
	if len(keys) != 1 {
		return "", fmt.Errorf("want exactly one master key in %s, found %v", keysDir, keys)
	}
	return strings.TrimSuffix(filepath.Base(keys[0]), ".key"), copyFile(keys[0], dst, 0o600)
}

func copyOnlyArchive(dir, dst string) error {
	archives, err := filepath.Glob(filepath.Join(dir, "*"+archiveExt))
	if err != nil {
		return err
	}
	if len(archives) != 1 {
		return fmt.Errorf("want exactly one archive in %s, found %v", dir, archives)
	}
	return copyFile(archives[0], dst, 0o644)
}

func copyFile(src, dst string, mode os.FileMode) error {
	raw, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	return os.WriteFile(dst, raw, mode)
}
