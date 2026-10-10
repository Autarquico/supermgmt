package database

import (
	"context"
	"fmt"
	"slices"
	"time"

	"github.com/autarquico/supermgmt/internal/domain"
	smerr "github.com/autarquico/supermgmt/internal/errors"
)

type (
	AddressFamily string
	AddressScope  string
	AddressSource string
)

const (
	FamilyIPv4 AddressFamily = "ipv4"
	FamilyIPv6 AddressFamily = "ipv6"

	ScopeGlobal   AddressScope = "global"
	ScopePrivate  AddressScope = "private"
	ScopeLink     AddressScope = "link"
	ScopeLoopback AddressScope = "loopback"

	SourceProbe    AddressSource = "probe"
	SourceProvider AddressSource = "provider"
)

func AllAddressFamilies() []AddressFamily { return []AddressFamily{FamilyIPv4, FamilyIPv6} }
func AllAddressScopes() []AddressScope {
	return []AddressScope{ScopeGlobal, ScopePrivate, ScopeLink, ScopeLoopback}
}
func AllAddressSources() []AddressSource { return []AddressSource{SourceProbe, SourceProvider} }

// NodeAddress is an address observed for a node (spec §9 node_addresses).
type NodeAddress struct {
	ID         domain.ID
	NodeID     domain.ID
	Address    string
	Family     AddressFamily
	Scope      AddressScope
	Source     AddressSource
	Preferred  bool
	LastSeenAt time.Time
}

func (a NodeAddress) validate() error {
	if a.Address == "" || !slices.Contains(AllAddressFamilies(), a.Family) ||
		!slices.Contains(AllAddressScopes(), a.Scope) || !slices.Contains(AllAddressSources(), a.Source) {
		return smerr.New(smerr.CodeInvalidArgument, "", "node address is invalid")
	}
	return nil
}

// ReplaceNodeAddresses makes the addresses of node reported by source equal to
// addrs: new ones are inserted, known ones updated in place (their id is kept)
// and the ones no longer reported are deleted. Addresses of other sources are
// untouched. Every entry must carry the given source.
func ReplaceNodeAddresses(ctx context.Context, q Querier, node domain.ID, source AddressSource, addrs []NodeAddress) error {
	for _, a := range addrs {
		if a.Source != source {
			return smerr.New(smerr.CodeInvalidArgument, "", "node address source differs from the replaced source")
		}
		if err := a.validate(); err != nil {
			return err
		}
	}
	for _, a := range addrs {
		_, err := q.ExecContext(ctx, `
			INSERT INTO node_addresses (id, node_id, address, family, scope, source, preferred, last_seen_at)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?)
			ON CONFLICT (node_id, address) DO UPDATE SET
				family = excluded.family, scope = excluded.scope, source = excluded.source,
				preferred = excluded.preferred, last_seen_at = excluded.last_seen_at`,
			a.ID, node, a.Address, a.Family, a.Scope, a.Source, a.Preferred, millis(a.LastSeenAt))
		if err != nil {
			return fmt.Errorf("upsert node address: %w", err)
		}
	}
	return deleteUnreportedAddresses(ctx, q, node, source, addrs)
}

func deleteUnreportedAddresses(ctx context.Context, q Querier, node domain.ID, source AddressSource, kept []NodeAddress) error {
	current, err := ListNodeAddresses(ctx, q, node)
	if err != nil {
		return err
	}
	reported := make(map[string]bool, len(kept))
	for _, a := range kept {
		reported[a.Address] = true
	}
	for _, a := range current {
		if a.Source != source || reported[a.Address] {
			continue
		}
		if _, err := q.ExecContext(ctx, `DELETE FROM node_addresses WHERE id = ?`, a.ID); err != nil {
			return fmt.Errorf("delete node address: %w", err)
		}
	}
	return nil
}

// ListNodeAddresses returns the addresses of node, preferred first.
func ListNodeAddresses(ctx context.Context, q Querier, node domain.ID) ([]NodeAddress, error) {
	return list(ctx, q, "node addresses", `
		SELECT id, node_id, address, family, scope, source, preferred, last_seen_at
		FROM node_addresses WHERE node_id = ? ORDER BY preferred DESC, address`,
		func(row scanner) (NodeAddress, error) {
			var (
				a      NodeAddress
				seenMs int64
			)
			err := row.Scan(&a.ID, &a.NodeID, &a.Address, &a.Family, &a.Scope, &a.Source, &a.Preferred, &seenMs)
			a.LastSeenAt = domain.FromUnixMillis(seenMs)
			return a, err
		}, node)
}
