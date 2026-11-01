package cloudflare

import (
	"context"
	"net/http"
	"net/url"
	"strings"
)

func zonePath(zoneID, rest string) (string, error) {
	if !validID(zoneID) {
		return "", invalid("invalid zone id %q", zoneID)
	}
	return "/zones/" + zoneID + rest, nil
}

// ZoneByName finds the zone of the account with exactly this name.
func (c *Client) ZoneByName(ctx context.Context, name string) (Zone, error) {
	name = strings.ToLower(name)
	if !validHostname(name) {
		return Zone{}, invalid("invalid zone name %q", name)
	}
	zones, err := listAll(ctx, c, "/zones", url.Values{"name": {name}, "account.id": {c.accountID}}, decodeZones)
	if err != nil {
		return Zone{}, err
	}
	var found []Zone
	for _, z := range zones {
		if z.Name == name && (z.AccountID == "" || z.AccountID == c.accountID) {
			found = append(found, z)
		}
	}
	switch len(found) {
	case 1:
		return found[0], nil
	case 0:
		return Zone{}, &APIError{Status: http.StatusNotFound, Message: "zone " + name + " is not in the account"}
	}
	return Zone{}, &APIError{Status: http.StatusConflict, Message: "zone " + name + " is ambiguous"}
}

// CreateTunnelCNAME creates the proxied CNAME that points hostname at a
// tunnel, carrying comment as the ownership marker. A hostname that already
// has a record is a conflict.
func (c *Client) CreateTunnelCNAME(ctx context.Context, zoneID, hostname, tunnelID, comment string) (DNSRecord, error) {
	path, err := zonePath(zoneID, "/dns_records")
	if err != nil {
		return DNSRecord{}, err
	}
	hostname = strings.ToLower(hostname)
	if !validHostname(hostname) || !validID(tunnelID) || !cleanText(comment) {
		return DNSRecord{}, invalid("invalid DNS record")
	}
	body := map[string]any{
		"type": "CNAME", "name": hostname, "content": TunnelTarget(tunnelID),
		"proxied": true, "ttl": 1, "comment": comment,
	}
	env, err := c.do(ctx, http.MethodPost, path, nil, body, maxObjectBody)
	if err != nil {
		return DNSRecord{}, err
	}
	record, err := decodeDNSRecord(env.Result)
	if err != nil {
		return DNSRecord{}, &outcomeUnknown{msg: "cloudflare: DNS record answer", err: err}
	}
	return record, nil
}

// FindDNSRecords lists the records of every type named exactly hostname.
func (c *Client) FindDNSRecords(ctx context.Context, zoneID, hostname string) ([]DNSRecord, error) {
	path, err := zonePath(zoneID, "/dns_records")
	if err != nil {
		return nil, err
	}
	hostname = strings.ToLower(hostname)
	if !validHostname(hostname) {
		return nil, invalid("invalid hostname %q", hostname)
	}
	all, err := listAll(ctx, c, path, url.Values{"name": {hostname}}, decodeDNSRecords)
	return exactly(all, hostname, func(r DNSRecord) string { return r.Name }, func(DNSRecord) bool { return true }), err
}

// DeleteDNSRecord deletes a record of the zone.
func (c *Client) DeleteDNSRecord(ctx context.Context, zoneID, recordID string) error {
	path, err := recordPath(zoneID, recordID)
	if err != nil {
		return err
	}
	_, err = c.do(ctx, http.MethodDelete, path, nil, nil, maxObjectBody)
	return err
}

// GetDNSRecord reads one record of the zone by ID.
func (c *Client) GetDNSRecord(ctx context.Context, zoneID, recordID string) (DNSRecord, error) {
	path, err := recordPath(zoneID, recordID)
	if err != nil {
		return DNSRecord{}, err
	}
	env, err := c.do(ctx, http.MethodGet, path, nil, nil, maxObjectBody)
	if err != nil {
		return DNSRecord{}, err
	}
	record, err := decodeDNSRecord(env.Result)
	if err != nil {
		return DNSRecord{}, &outcomeUnknown{msg: "cloudflare: DNS record answer", err: err}
	}
	return record, nil
}

// UpdateDNSRecord points a record at a new target. Only content is sent, so
// the record keeps its ID, comment, type and proxying.
func (c *Client) UpdateDNSRecord(ctx context.Context, zoneID, recordID, content string) (DNSRecord, error) {
	path, err := recordPath(zoneID, recordID)
	if err != nil {
		return DNSRecord{}, err
	}
	content = strings.ToLower(content)
	if !validHostname(content) {
		return DNSRecord{}, invalid("invalid record content %q", content)
	}
	env, err := c.do(ctx, http.MethodPatch, path, nil, map[string]any{"content": content}, maxObjectBody)
	if err != nil {
		return DNSRecord{}, err
	}
	record, err := decodeDNSRecord(env.Result)
	if err != nil {
		return DNSRecord{}, &outcomeUnknown{msg: "cloudflare: DNS record answer", err: err}
	}
	return record, nil
}

func recordPath(zoneID, recordID string) (string, error) {
	if !validID(recordID) {
		return "", invalid("invalid record id %q", recordID)
	}
	return zonePath(zoneID, "/dns_records/"+recordID)
}
