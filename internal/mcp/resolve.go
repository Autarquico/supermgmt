package mcp

import (
	"context"
	"fmt"
	"strings"

	"github.com/autarquico/supermgmt/internal/api/wire"
	"github.com/autarquico/supermgmt/internal/domain"
)

// maxResolvePages bounds the pages read to resolve one name; past it the
// caller must use an id.
const maxResolvePages = 50

// Names are resolved against the raw API values, never against the sanitized
// view copies, so sanitation can never retarget a write. The result is
// always an id.

// resolveNode accepts a node id or an exact node name.
func resolveNode(ctx context.Context, api API, ref string) (domain.ID, error) {
	if id, err := domain.ParseID(ref); err == nil {
		return id, nil
	}
	node, err := findUnique(ctx, "node", ref,
		func(cursor string) (wire.Page[wire.Node], error) {
			return api.ListNodes(ctx, wire.NodeQuery{PageQuery: resolvePage(cursor)})
		},
		func(n wire.Node) bool { return n.Name == ref })
	return node.ID, err
}

// resolveService accepts a service id or "name@node". The node is whatever
// follows the last '@': systemd instance names (getty@tty1.service) contain
// '@', node names do not.
func resolveService(ctx context.Context, api API, ref string) (domain.ID, error) {
	if id, err := domain.ParseID(ref); err == nil {
		return id, nil
	}
	at := strings.LastIndexByte(ref, '@')
	if at <= 0 || at == len(ref)-1 {
		return "", invalidArgument(fmt.Sprintf("service %q is neither an id nor name@node", ref))
	}
	name, nodeRef := ref[:at], ref[at+1:]
	node, err := resolveNode(ctx, api, nodeRef)
	if err != nil {
		return "", err
	}
	service, err := findUnique(ctx, "service", ref,
		func(cursor string) (wire.Page[wire.Service], error) {
			return api.ListServices(ctx, node, resolvePage(cursor))
		},
		func(s wire.Service) bool { return s.Name == name })
	return service.ID, err
}

// resolveApp accepts an app id or an exact app name.
func resolveApp(ctx context.Context, api API, ref string) (domain.ID, error) {
	if id, err := domain.ParseID(ref); err == nil {
		return id, nil
	}
	app, err := findUnique(ctx, "app", ref,
		func(cursor string) (wire.Page[wire.App], error) { return api.ListApps(ctx, resolvePage(cursor)) },
		func(a wire.App) bool { return a.Name == ref })
	return app.ID, err
}

func resolvePage(cursor string) wire.PageQuery {
	return wire.PageQuery{Cursor: cursor, Limit: wire.MaxLimit}
}

// findUnique pages through fetch and returns the single item that matches.
// No match is NOT_FOUND, several are AMBIGUOUS_TARGET, and a listing longer
// than maxResolvePages is refused because uniqueness cannot be shown.
func findUnique[T any](
	ctx context.Context, kind, ref string,
	fetch func(cursor string) (wire.Page[T], error), matches func(T) bool,
) (found T, _ error) {
	var hits []T
	cursor := ""
	for range maxResolvePages {
		if err := ctx.Err(); err != nil {
			return found, err
		}
		page, err := fetch(cursor)
		if err != nil {
			return found, err
		}
		for _, item := range page.Items {
			if matches(item) {
				hits = append(hits, item)
			}
		}
		if page.NextCursor == "" {
			return uniqueHit(kind, ref, hits)
		}
		cursor = page.NextCursor
	}
	return found, invalidArgument(fmt.Sprintf("too many %ss to resolve %q by name; use an id", kind, ref))
}

func uniqueHit[T any](kind, ref string, hits []T) (found T, _ error) {
	switch len(hits) {
	case 0:
		return found, targetNotFound(fmt.Sprintf("no %s matches %q", kind, ref))
	case 1:
		return hits[0], nil
	}
	return found, ambiguousTarget(fmt.Sprintf("%d %ss match %q; use an id", len(hits), kind, ref))
}
