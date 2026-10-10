package docker

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/autarquico/supermgmt/internal/textsafe"

	smerr "github.com/autarquico/supermgmt/internal/errors"
	"github.com/autarquico/supermgmt/internal/transport"
)

// containerState is both the pre-state recorded in the intent and the
// observed fingerprint (State.StartedAt is what restart evidence compares).
type containerState struct {
	StartedAt string `json:"started_at"`
	Running   bool   `json:"running"`
	Status    string `json:"status"`
}

func (c containerState) marshal() (json.RawMessage, error) {
	b, err := json.Marshal(c)
	if err != nil {
		return nil, fmt.Errorf("encode container state: %w", err)
	}
	return b, nil
}

// startedAfter reports whether the container started strictly after prev did.
func (c containerState) startedAfter(prev containerState) bool {
	now, errNow := time.Parse(time.RFC3339Nano, c.StartedAt)
	then, errThen := time.Parse(time.RFC3339Nano, prev.StartedAt)
	return errNow == nil && errThen == nil && now.After(then)
}

// inspected is the part of `docker inspect` the adapter reads.
type inspected struct {
	ID     string `json:"Id"`
	Name   string `json:"Name"`
	Image  string `json:"Image"`
	Config struct {
		Image  string            `json:"Image"`
		Labels map[string]string `json:"Labels"`
	} `json:"Config"`
	State struct {
		Status    string `json:"Status"`
		Running   bool   `json:"Running"`
		StartedAt string `json:"StartedAt"`
		Health    *struct {
			Status string `json:"Status"`
		} `json:"Health"`
	} `json:"State"`
	NetworkSettings struct {
		Ports map[string][]struct {
			HostIP   string `json:"HostIp"`
			HostPort string `json:"HostPort"`
		} `json:"Ports"`
	} `json:"NetworkSettings"`
}

func (c inspected) state() containerState {
	return containerState{StartedAt: textsafe.Line(c.State.StartedAt), Running: c.State.Running, Status: textsafe.Line(c.State.Status)}
}

func decodeInspect(out []byte) ([]inspected, error) {
	var all []inspected
	if len(strings.TrimSpace(string(out))) == 0 {
		return nil, nil
	}
	if err := json.Unmarshal(out, &all); err != nil {
		return nil, smerr.New(smerr.CodeProviderError, "", "docker inspect returned unreadable output")
	}
	return all, nil
}

// inspect reads the state of one container.
func inspect(ctx context.Context, ex transport.Executor, id string) (containerState, error) {
	res, err := read(ctx, ex, "docker.inspect", map[string]string{"container": id})
	if err != nil {
		return containerState{}, err
	}
	if res.ExitStatus != 0 {
		return containerState{}, smerr.New(smerr.CodeNotFound, "", "container not found or docker is not accessible")
	}
	if res.Truncated {
		return containerState{}, smerr.New(smerr.CodeInternal, "", "docker inspect output exceeds the template limit")
	}
	all, err := decodeInspect(res.Stdout)
	if err != nil {
		return containerState{}, err
	}
	if len(all) != 1 {
		return containerState{}, smerr.New(smerr.CodeNotFound, "", "container not found")
	}
	return all[0].state(), nil
}
