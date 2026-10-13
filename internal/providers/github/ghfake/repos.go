package ghfake

import (
	"crypto/sha1" //nolint:gosec // git blob ids are SHA-1 by definition
	"encoding/base64"
	"fmt"
	"net/http"
	"regexp"
	"slices"
	"strconv"
	"strings"
)

// maxInlineContent is the largest file GitHub returns inline (1 MiB); larger
// ones come back with encoding "none" and no content.
const maxInlineContent = 1 << 20

var commitPattern = regexp.MustCompile(`^[0-9a-f]{40}$`)

// Repo is a repository the fake knows.
type Repo struct {
	ID            int64
	OwnerID       int64
	Owner         string
	Name          string
	DefaultBranch string
	Private       bool
}

// File is a file at one commit.
type File struct {
	Path    string
	Content []byte
}

type fileKey struct {
	repoID int64
	commit string
	path   string
}

// BlobSHA is the git blob id of content.
func BlobSHA(content []byte) string {
	h := sha1.New() //nolint:gosec // see import
	_, _ = fmt.Fprintf(h, "blob %d\x00", len(content))
	_, _ = h.Write(content)
	return fmt.Sprintf("%x", h.Sum(nil))
}

// AddRepo registers a repository. A duplicate ID or owner/name fails the test.
func (f *Fake) AddRepo(r Repo) {
	f.t.Helper()
	f.mu.Lock()
	defer f.mu.Unlock()
	if r.ID <= 0 || r.Owner == "" || r.Name == "" || slices.ContainsFunc(f.repos, func(o Repo) bool {
		return o.ID == r.ID || (o.Owner == r.Owner && o.Name == r.Name)
	}) {
		f.t.Fatalf("ghfake: invalid or duplicate repository %+v", r)
	}
	if r.DefaultBranch == "" {
		r.DefaultBranch = "main"
	}
	f.repos = append(f.repos, r)
}

// AddFile puts a file at an exact commit of a registered repository.
func (f *Fake) AddFile(repoID int64, commit, path string, content []byte) {
	f.t.Helper()
	f.mu.Lock()
	defer f.mu.Unlock()
	if !commitPattern.MatchString(commit) || path == "" || strings.HasPrefix(path, "/") ||
		!slices.ContainsFunc(f.repos, func(r Repo) bool { return r.ID == repoID }) {
		f.t.Fatalf("ghfake: invalid file %d@%s:%s", repoID, commit, path)
	}
	f.files[fileKey{repoID, commit, path}] = File{Path: path, Content: slices.Clone(content)}
}

func (f *Fake) registerRepoRoutes() {
	f.Handle("GET /repositories/{id}", nil, f.getRepositoryByID)
	f.Handle("GET /user/repos", []string{"per_page", "page"}, f.listRepositories)
	f.Handle("GET /repos/{owner}/{repo}/contents/{path...}", []string{"ref"}, f.getContents)
}

func (f *Fake) getRepositoryByID(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err == nil {
		f.mu.Lock()
		i := slices.IndexFunc(f.repos, func(o Repo) bool { return o.ID == id })
		var repo Repo
		if i >= 0 {
			repo = f.repos[i]
		}
		f.mu.Unlock()
		if i >= 0 {
			WriteJSON(w, repoDocument(repo))
			return
		}
	}
	WriteError(w, http.StatusNotFound, "Not Found")
}

func (f *Fake) listRepositories(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	repos := slices.Clone(f.repos)
	f.mu.Unlock()
	lo, hi, ok := Paginate(w, r, len(repos))
	if !ok {
		return
	}
	page := make([]map[string]any, 0, hi-lo)
	for _, repo := range repos[lo:hi] {
		page = append(page, repoDocument(repo))
	}
	WriteJSON(w, page)
}

func repoDocument(r Repo) map[string]any {
	return map[string]any{
		"id":             r.ID,
		"name":           r.Name,
		"full_name":      r.Owner + "/" + r.Name,
		"private":        r.Private,
		"html_url":       "https://github.com/" + r.Owner + "/" + r.Name,
		"default_branch": r.DefaultBranch,
		"owner":          map[string]any{"login": r.Owner, "id": r.OwnerID},
	}
}

func (f *Fake) getContents(w http.ResponseWriter, r *http.Request) {
	ref := r.URL.Query().Get("ref")
	if !commitPattern.MatchString(ref) {
		WriteError(w, http.StatusUnprocessableEntity, "Validation Failed: ref must be a full commit sha")
		return
	}
	repo, ok := f.repoByName(r.PathValue("owner"), r.PathValue("repo"))
	if !ok {
		WriteError(w, http.StatusNotFound, "Not Found")
		return
	}
	path := r.PathValue("path")
	f.mu.Lock()
	file, isFile := f.files[fileKey{repo.ID, ref, path}]
	entries := f.directoryAt(repo.ID, ref, path)
	f.mu.Unlock()
	switch {
	case isFile:
		WriteJSON(w, fileDocument(file))
	case len(entries) > 0:
		WriteJSON(w, entries)
	default:
		WriteError(w, http.StatusNotFound, "Not Found")
	}
}

func (f *Fake) repoByName(owner, name string) (Repo, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	i := slices.IndexFunc(f.repos, func(r Repo) bool { return r.Owner == owner && r.Name == name })
	if i < 0 {
		return Repo{}, false
	}
	return f.repos[i], true
}

// directoryAt lists the files directly under dir, as GitHub lists a directory.
// The caller holds f.mu.
func (f *Fake) directoryAt(repoID int64, commit, dir string) []map[string]any {
	var entries []map[string]any
	for key, file := range f.files {
		if key.repoID == repoID && key.commit == commit && strings.HasPrefix(key.path, dir+"/") {
			entries = append(entries, map[string]any{"type": "file", "path": file.Path, "name": file.Path[strings.LastIndex(file.Path, "/")+1:]})
		}
	}
	slices.SortFunc(entries, func(a, b map[string]any) int { return strings.Compare(a["path"].(string), b["path"].(string)) })
	return entries
}

func fileDocument(file File) map[string]any {
	doc := map[string]any{
		"type": "file", "path": file.Path, "name": file.Path[strings.LastIndex(file.Path, "/")+1:],
		"size": len(file.Content), "sha": BlobSHA(file.Content),
		"encoding": "none", "content": "",
	}
	if len(file.Content) <= maxInlineContent {
		doc["encoding"] = "base64"
		doc["content"] = wrapBase64(base64.StdEncoding.EncodeToString(file.Content))
	}
	return doc
}

// wrapBase64 breaks the encoding into 60-character lines, as GitHub does.
func wrapBase64(s string) string {
	var b strings.Builder
	for len(s) > 60 {
		b.WriteString(s[:60])
		b.WriteByte('\n')
		s = s[60:]
	}
	b.WriteString(s)
	if b.Len() > 0 {
		b.WriteByte('\n')
	}
	return b.String()
}
