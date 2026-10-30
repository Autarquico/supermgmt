package pveid

import (
	"bytes"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"regexp"
	"slices"
	"strings"

	"github.com/autarquico/supermgmt/internal/audit"
)

// ErrUnreadable is every parser's refusal. It never carries the input: some of
// these answers hold a secret.
var ErrUnreadable = errors.New("unreadable JSON output")

func unmarshalRows(out []byte) ([]map[string]any, error) {
	var rows []map[string]any
	if json.Unmarshal(out, &rows) != nil {
		return nil, ErrUnreadable
	}
	return rows, nil
}

// ParseListed reports whether a `pveum ... list` answer has a row whose string
// field equals want.
func ParseListed(out []byte, field, want string) (bool, error) {
	rows, err := unmarshalRows(out)
	if err != nil {
		return false, err
	}
	for _, r := range rows {
		if v, _ := r[field].(string); v == want {
			return true, nil
		}
	}
	return false, nil
}

// ParseACLs reads `pveum acl list`: user and token entries, nothing else.
func ParseACLs(out []byte) ([]ACL, error) {
	var rows []struct {
		Path   string `json:"path"`
		RoleID string `json:"roleid"`
		Type   string `json:"type"`
		UGID   string `json:"ugid"`
	}
	if json.Unmarshal(out, &rows) != nil {
		return nil, ErrUnreadable
	}
	var acls []ACL
	for _, r := range rows {
		switch r.Type {
		case "user":
			acls = append(acls, ACL{Path: r.Path, Role: r.RoleID, User: r.UGID})
		case "token":
			acls = append(acls, ACL{Path: r.Path, Role: r.RoleID, Token: r.UGID})
		}
	}
	return acls, nil
}

// ParseOwnedToken reports whether `pveum user token list <user>` holds token id
// carrying this identity's comment; a same-named token without it counts as
// absent, so it is never revoked.
func ParseOwnedToken(out []byte, user, id string) (bool, error) {
	rows, err := unmarshalRows(out)
	if err != nil {
		return false, err
	}
	for _, r := range rows {
		tokenID, _ := r["tokenid"].(string)
		comment, _ := r["comment"].(string)
		if tokenID == id && comment == TokenComment(user) {
			return true, nil
		}
	}
	return false, nil
}

// tokenSecretPattern is a token value as one safe word: it can be joined to
// "user!id=" and sent in an Authorization header without quoting.
var tokenSecretPattern = regexp.MustCompile(`^[A-Za-z0-9_-]{16,128}$`)

// ParseTokenAdd reads the answer of `pveum user token add <user> <id>
// --output-format json`: exactly one object with full-tokenid (the token that
// was asked for), value (its secret) and the info object pveum adds. Any other
// shape is refused with ErrUnreadable and nothing of the input.
func ParseTokenAdd(out []byte, user, id string) (audit.Secret, error) {
	dec := json.NewDecoder(bytes.NewReader(out))
	dec.DisallowUnknownFields()
	var reply struct {
		FullTokenID string          `json:"full-tokenid"`
		Info        json.RawMessage `json:"info"`
		Value       string          `json:"value"`
	}
	if dec.Decode(&reply) != nil {
		return "", ErrUnreadable
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return "", ErrUnreadable
	}
	if reply.FullTokenID != user+"!"+id || !tokenSecretPattern.MatchString(reply.Value) {
		return "", ErrUnreadable
	}
	return audit.Secret(reply.Value), nil
}

func rowOf(out []byte, field, want string) (map[string]any, error) {
	rows, err := unmarshalRows(out)
	if err != nil {
		return nil, err
	}
	for _, r := range rows {
		if v, _ := r[field].(string); v == want {
			return r, nil
		}
	}
	return nil, nil
}

// ParseOwnedUser reads `pveum user list`: present says the user is listed, owned
// that it carries this identity's mark (Mark of the id its name was derived from).
func ParseOwnedUser(out []byte, user string) (present, owned bool, err error) {
	row, err := rowOf(out, "userid", user)
	if err != nil || row == nil {
		return false, false, err
	}
	comment, _ := row["comment"].(string)
	return true, comment == TokenComment(user), nil
}

// ParseRolePrivileges reads `pveum role list`: the privileges of role, sorted,
// and whether it is listed at all.
func ParseRolePrivileges(out []byte, role string) (privileges []string, present bool, err error) {
	row, err := rowOf(out, "roleid", role)
	if err != nil || row == nil {
		return nil, false, err
	}
	list, _ := row["privs"].(string)
	if list != "" {
		privileges = strings.Split(list, ",")
		slices.Sort(privileges)
	}
	return privileges, true, nil
}

// maxCAPEM bounds the CA read from a host; a root certificate is about 2 KiB.
const maxCAPEM = 16 << 10

// ErrNotACA is every CA parser's refusal; it carries none of the input.
var ErrNotACA = errors.New("not exactly one CA certificate in PEM form")

// ParseCAPEM reads the cluster CA a host gave: exactly one CERTIFICATE block
// without headers, nothing but white space around it, and a certificate that is
// a CA. It returns the certificate and its canonical PEM, which is what gets
// recorded.
func ParseCAPEM(in []byte) (*x509.Certificate, string, error) {
	if len(in) > maxCAPEM || !bytes.HasPrefix(bytes.TrimSpace(in), []byte("-----BEGIN CERTIFICATE-----")) {
		return nil, "", ErrNotACA
	}
	block, rest := pem.Decode(in)
	if block == nil || block.Type != "CERTIFICATE" || len(block.Headers) != 0 || len(bytes.TrimSpace(rest)) != 0 {
		return nil, "", ErrNotACA
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil || !cert.BasicConstraintsValid || !cert.IsCA {
		return nil, "", ErrNotACA
	}
	return cert, string(pem.EncodeToMemory(block)), nil
}

// SupportedMajor is the only Proxmox VE major version SuperMgmt supports.
const SupportedMajor = 9

var managerVersionPattern = regexp.MustCompile(`pve-manager/(\d+(?:\.\d+){0,2})`)

// ParseManagerVersion reads the pve-manager version out of `pveversion`.
func ParseManagerVersion(out string) (string, bool) {
	m := managerVersionPattern.FindStringSubmatch(out)
	if m == nil {
		return "", false
	}
	return m[1], true
}
