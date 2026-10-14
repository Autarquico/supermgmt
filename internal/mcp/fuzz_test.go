package mcp

import (
	"context"
	"encoding/json"
	"testing"

	sdk "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/autarquico/supermgmt/internal/domain"
)

// toolFuzzSession serves NewServer over the SDK's in-memory transport. Unlike
// serverSession it takes a testing.TB, so a fuzz target can build it once.
func toolFuzzSession(tb testing.TB, api API, writeTools bool) *sdk.ClientSession {
	tb.Helper()
	ctx := context.Background()
	server := NewServer(api, Options{WriteTools: writeTools, Version: "0"})
	serverEnd, clientEnd := sdk.NewInMemoryTransports()
	serverSession, err := server.Connect(ctx, serverEnd, nil)
	if err != nil {
		tb.Fatalf("server connect: %v", err)
	}
	tb.Cleanup(func() { _ = serverSession.Close() })
	client := sdk.NewClient(&sdk.Implementation{Name: "fuzz-client", Version: "0"}, nil)
	session, err := client.Connect(ctx, clientEnd, nil)
	if err != nil {
		tb.Fatalf("client connect: %v", err)
	}
	tb.Cleanup(func() { _ = session.Close() })
	return session
}

// Every tool takes its arguments from an untrusted model. Whatever they are,
// a call returns a result or a protocol error, and with write tools disabled
// it never reaches a write endpoint.
func FuzzToolArguments(f *testing.F) {
	readOnly := newServerFakeAPI()
	enabled := toolFuzzSession(f, newServerFakeAPI(), true)
	disabled := toolFuzzSession(f, readOnly, false)
	listed, err := enabled.ListTools(context.Background(), nil)
	if err != nil {
		f.Fatal(err)
	}
	tools := toolNames(listed.Tools)
	for i := range tools {
		f.Add(uint8(i), `{}`, true)
		f.Add(uint8(i), `{"node":"web-1","service":"nginx@web-1","app":"shop","plan_id":"x","plan_hash":"y","limit":-1}`, false)
		f.Add(uint8(i), `{"node":null,"limit":9999999999999999999,"since":"not a time"}`, true)
	}
	f.Fuzz(func(t *testing.T, tool uint8, arguments string, writesEnabled bool) {
		if !json.Valid([]byte(arguments)) {
			return
		}
		session := disabled
		if writesEnabled {
			session = enabled
		}
		params := &sdk.CallToolParams{Name: tools[int(tool)%len(tools)], Arguments: json.RawMessage(arguments)}
		if _, err := session.CallTool(context.Background(), params); err != nil {
			return
		}
		if !writesEnabled && len(readOnly.submits)+len(readOnly.deploymentRequests)+len(readOnly.rollbacks) > 0 {
			t.Fatalf("%s wrote with write tools disabled", params.Name)
		}
	})
}

// A reference resolves to an id or fails; a canonical id resolves to itself
// without a lookup, and anything else only resolves to a listed object.
func FuzzResolveRef(f *testing.F) {
	for _, seed := range []string{
		string(readNodeID), "web-1", "nginx@web-1", "getty@tty1.service@web-1", "@", "a@", "@web-1", "shop", "",
		"0190A5C3-7B1E-7C3A-9D2E-1A2B3C4D5E01",
	} {
		f.Add(seed)
	}
	api := readTestAPI()
	known := map[domain.ID]bool{readNodeID: true, readServiceID: true, readAppID: true}
	f.Fuzz(func(t *testing.T, ref string) {
		ctx := context.Background()
		resolvers := map[string]func(context.Context, API, string) (domain.ID, error){
			"node": resolveNode, "service": resolveService, "app": resolveApp,
		}
		for kind, resolve := range resolvers {
			id, err := resolve(ctx, api, ref)
			switch {
			case err != nil:
			case id == "":
				t.Fatalf("%s %q resolved to an empty id", kind, ref)
			case domain.ID(ref) == id:
			case !known[id]:
				t.Fatalf("%s %q resolved to unlisted %q", kind, ref, id)
			}
		}
	})
}
