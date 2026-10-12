// Command fakeapi serves the fake Proxmox VE API (internal/providers/proxmox/pvefake) from a
// container: the REST API with TLS on :8006, and a plain administration endpoint on :8007 through
// which the pvesim controller mirrors users, roles, ACLs, tokens and guests into it.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/autarquico/supermgmt/internal/providers/proxmox/pvefake"
	"github.com/autarquico/supermgmt/test/e2e/pvesim"
)

// processTB lets the fake, written for tests, run in a process of its own: a failed invariant ends
// the process, which the harness notices.
type processTB struct{ testing.TB }

func (processTB) Helper()                   {}
func (processTB) Cleanup(func())            {}
func (processTB) Fatalf(f string, a ...any) { log.Fatalf(f, a...) }
func (processTB) Fatal(a ...any)            { log.Fatal(a...) }
func (processTB) Logf(f string, a ...any)   { log.Printf(f, a...) }

func main() {
	topologyPath := flag.String("topology", "/topology.json", "topology document")
	apiAddr := flag.String("api", ":8006", "address of the TLS API")
	adminAddr := flag.String("admin", ":8007", "address of the administration endpoint")
	flag.Parse()

	raw, err := os.ReadFile(*topologyPath)
	if err != nil {
		log.Fatal(err)
	}
	var topo pvesim.Topology
	if err := json.Unmarshal(raw, &topo); err != nil {
		log.Fatal(err)
	}
	// Real PVE stamps tasks with wall time; SuperMgmt checks a returned UPID
	// against the dispatch window, so the fake must too.
	fake := pvefake.New(processTB{}, pvefake.WithClock(time.Now)) //nolint:forbidigo // the fake host's own clock
	fake.AddNode(topo.Node)
	for _, st := range topo.Storages {
		fake.AddStorage(pvefake.Storage{ID: st.ID, Node: topo.Node, Plugin: st.Type, Content: strings.Split(st.Content, ","), Total: int64(st.TotalGB) << 30})
	}
	go forward(*apiAddr, fake)
	log.Fatal((&http.Server{Addr: *adminAddr, Handler: adminHandler(fake, topo.Node), ReadHeaderTimeout: 10 * time.Second}).ListenAndServe())
}

// forward exposes the fake's loopback listener on addr: plain TCP, so the fake's TLS is untouched.
func forward(addr string, fake *pvefake.Fake) {
	ln, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp", addr)
	if err != nil {
		log.Fatal(err)
	}
	for {
		in, err := ln.Accept()
		if err != nil {
			log.Fatal(err)
		}
		go func() {
			out, err := fake.Dial("tcp", "")
			if err != nil {
				_ = in.Close()
				return
			}
			go func() { _, _ = io.Copy(out, in); _ = out.Close() }()
			_, _ = io.Copy(in, out)
			_ = in.Close()
		}()
	}
}

func adminHandler(fake *pvefake.Fake, node string) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, "ok") })
	mux.HandleFunc("GET /ca", func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write(fake.CAPEM()) })
	mux.HandleFunc("POST /guest", decode(func(g pvesim.FakeGuest) (any, error) {
		fake.RemoveGuest(g.VMID)
		fake.AddGuest(pvefake.Guest{Node: node, Type: "lxc", VMID: g.VMID, Name: g.Name, Status: g.Status, MaxCPU: 1, MaxMem: 512 << 20, MaxDisk: 4 << 30})
		return nil, nil
	}))
	mux.HandleFunc("DELETE /guest/{vmid}", func(w http.ResponseWriter, r *http.Request) {
		id, err := strconv.Atoi(r.PathValue("vmid"))
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		fake.RemoveGuest(id)
	})
	mux.HandleFunc("POST /role", decode(func(r pvesim.RoleRequest) (any, error) {
		fake.SetRole(r.Name, r.Privileges...)
		return nil, nil
	}))
	mux.HandleFunc("POST /token", decode(func(r pvesim.TokenRequest) (any, error) {
		full := fake.AddToken(r.User, r.ID, r.Privsep)
		_, secret, ok := strings.Cut(full, "=")
		if !ok {
			return nil, fmt.Errorf("unexpected token %q", full)
		}
		return map[string]string{"secret": secret}, nil
	}))
	mux.HandleFunc("POST /grant", decode(func(g pvesim.GrantRequest) (any, error) {
		fake.Grant(g.Subject, g.Path, g.Role, g.Propagate)
		return nil, nil
	}))
	mux.HandleFunc("POST /inject", decode(func(r pvesim.InjectRequest) (any, error) {
		fault, err := faultOf(r)
		if err != nil {
			return nil, err
		}
		fake.Inject(pvefake.Rule{Method: r.Method, PathSuffix: r.PathSuffix, Times: r.Times, Fault: fault})
		return nil, nil
	}))
	mux.HandleFunc("POST /revoke", decode(func(g pvesim.GrantRequest) (any, error) {
		fake.Revoke(g.Subject, g.Path, g.Role)
		return nil, nil
	}))
	return mux
}

func faultOf(r pvesim.InjectRequest) (pvefake.Fault, error) {
	switch r.Kind {
	case "respond":
		return pvefake.Respond(r.Code, r.Body), nil
	case "drop_before":
		return pvefake.DropBefore(), nil
	case "drop_after":
		return pvefake.DropAfter(), nil
	case "hang":
		return pvefake.Hang(), nil
	}
	return pvefake.Fault{}, fmt.Errorf("unknown fault kind %q", r.Kind)
}

// decode adapts a typed handler to HTTP: JSON in, JSON out.
func decode[T any](h func(T) (any, error)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var in T
		if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		out, err := h(in)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		if out == nil {
			out = map[string]bool{"ok": true}
		}
		_ = json.NewEncoder(w).Encode(out)
	}
}
