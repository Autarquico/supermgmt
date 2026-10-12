package pvesim

import (
	"context"
	"crypto/rand"
	"errors"
	"sort"
	"strings"
	"sync"
)

// Sim is the simulated PVE host: its state and the tools that change it.
type Sim struct {
	cfg  Topology
	eng  Engine
	api  API
	host string // the container the shims run in: pct push reads its files

	mu        sync.Mutex
	guests    map[int]*guest
	templates map[string]bool // downloaded template volumes
	users     map[string]*pveUser
	roles     map[string]*pveRole
	acls      []pveACL
}

// New builds a Sim. host is the name of the container the shims run in.
func New(cfg Topology, eng Engine, api API, host string) *Sim {
	s := &Sim{
		cfg: cfg, eng: eng, api: api, host: host,
		guests: map[int]*guest{}, templates: map[string]bool{}, users: map[string]*pveUser{}, roles: builtinRoles(),
	}
	for _, v := range cfg.Present {
		s.templates[v] = true
	}
	return s
}

// Run executes one tool run.
func (s *Sim) Run(ctx context.Context, req Request) Response {
	var run func(context.Context, []string, []byte) Response
	switch req.Tool {
	case "pct":
		run = s.pct
	case "pvesh":
		run = text(s.pvesh)
	case "pveum":
		run = text(s.pveum)
	case "pvesm":
		run = text(s.pvesm)
	case "pveam":
		run = text(s.pveam)
	case "pveversion":
		run = text(s.pveversion)
	default:
		return failure(die("pvesim: %q is not a Proxmox tool this simulation provides", req.Tool))
	}
	return run(ctx, req.Args, req.Stdin)
}

func text(h func(context.Context, []string) (string, error)) func(context.Context, []string, []byte) Response {
	return func(ctx context.Context, args []string, _ []byte) Response {
		out, err := h(ctx, args)
		if err != nil {
			return failure(err)
		}
		return Response{Stdout: []byte(out)}
	}
}

func failure(err error) Response {
	var te *toolError
	if errors.As(err, &te) {
		return Response{Stderr: []byte(te.msg + "\n"), Code: te.code}
	}
	return Response{Stderr: []byte(err.Error() + "\n"), Code: 255}
}

// subcommand picks the grammar for args by its leading words ("user token add"); it returns the
// grammar and the remaining arguments.
func subcommand(tool string, table map[string]command, args []string) (command, []string, error) {
	for words := 3; words >= 1; words-- {
		if len(args) < words {
			continue
		}
		key := strings.Join(args[:words], " ")
		if cmd, ok := table[key]; ok {
			return cmd, args[words:], nil
		}
	}
	names := make([]string, 0, len(table))
	for k := range table {
		names = append(names, k)
	}
	sort.Strings(names)
	if len(args) == 0 {
		return command{}, nil, die("USAGE: %s <command> [ARGS] [OPTIONS]\n  commands: %s", tool, strings.Join(names, ", "))
	}
	return command{}, nil, die("unknown command '%s'\nUSAGE: %s <command> [ARGS] [OPTIONS]\n  commands: %s", strings.Join(args, " "), tool, strings.Join(names, ", "))
}

func randomSuffix() string { return strings.ToLower(rand.Text()[:6]) }
