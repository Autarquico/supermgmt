package pvefake

import (
	"sort"
	"strings"
)

type aclEntry struct {
	path      string
	subject   string // "user@realm" or "user@realm!tokenid"
	role      string
	propagate bool
}

type privSet map[string]bool

func intersect(a, b privSet) privSet {
	out := privSet{}
	for p := range a {
		if b[p] {
			out[p] = true
		}
	}
	return out
}

// parents lists path, then each ancestor up to "/".
func parents(path string) []string {
	out := []string{path}
	for path != "/" && path != "" {
		i := strings.LastIndex(path, "/")
		path = path[:i]
		if path == "" {
			path = "/"
		}
		out = append(out, path)
	}
	return out
}

// subjectPrivs is the set of privileges one subject holds on path: the roles
// at the deepest level that has entries for it (entries on ancestors count
// only when they propagate); NoAccess cancels the level.
func (f *Fake) subjectPrivs(subject, path string) privSet {
	for i, level := range parents(path) {
		privs, found := privSet{}, false
		for _, e := range f.acl {
			if e.subject != subject || e.path != level || (i > 0 && !e.propagate) {
				continue
			}
			found = true
			if e.role == "NoAccess" {
				return privSet{}
			}
			for p := range f.roles[e.role] {
				privs[p] = true
			}
		}
		if found {
			return privs
		}
	}
	return privSet{}
}

// effective is what the token may do on path: its user's privileges
// intersected with its own when privilege separation is on.
func (f *Fake) effective(tokenID, path string) privSet {
	user, _, _ := strings.Cut(tokenID, "!")
	userPrivs := f.subjectPrivs(user, path)
	if !f.tokens[tokenID].privsep {
		return userPrivs
	}
	return intersect(userPrivs, f.subjectPrivs(tokenID, path))
}

func (f *Fake) allowed(tokenID, path, priv string) bool { return f.effective(tokenID, path)[priv] }

// permissions is GET /access/permissions: for every path the token's user or
// the token has an ACL entry on, the effective privileges there (flag 1 when
// an entry on that path propagates).
func (f *Fake) permissions(tokenID string) map[string]map[string]int {
	user, _, _ := strings.Cut(tokenID, "!")
	out := map[string]map[string]int{}
	var paths []string
	for _, e := range f.acl {
		if e.subject == user || e.subject == tokenID {
			paths = append(paths, e.path)
		}
	}
	sort.Strings(paths)
	for _, path := range paths {
		privs := f.effective(tokenID, path)
		if len(privs) == 0 {
			continue
		}
		flag := 0
		for _, e := range f.acl {
			if (e.subject == user || e.subject == tokenID) && e.path == path && e.propagate {
				flag = 1
			}
		}
		m := map[string]int{}
		for p := range privs {
			m[p] = flag
		}
		out[path] = m
	}
	return out
}
