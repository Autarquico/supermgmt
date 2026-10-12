package github

import (
	"bytes"
	"context"
	"crypto/sha1" //nolint:gosec // git blob ids are SHA-1 by definition
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"unicode"
)

// maxContentsBody bounds a contents answer: MaxFileBytes of base64 with its
// line breaks, plus the JSON around it.
const maxContentsBody = 512 << 10

// ErrFileTooLarge means a file exceeds the size the caller allowed.
var ErrFileTooLarge = errors.New("github: file too large")

type wireContent struct {
	Type     string `json:"type"`
	Encoding string `json:"encoding"`
	Path     string `json:"path"`
	SHA      string `json:"sha"`
	Size     int64  `json:"size"`
	Content  string `json:"content"`
}

// File reads path at the exact commit sha through the JSON contents API. The
// answer must be a regular file of at most limit bytes (0 or above MaxFileBytes:
// MaxFileBytes), for that path, whose content hashes to the blob sha GitHub
// reports.
func (c *client) File(ctx context.Context, r Repo, sha, path string, limit int64) (File, error) {
	base, err := repoPath(r)
	if err != nil {
		return File{}, err
	}
	if !commitPattern.MatchString(sha) {
		return File{}, fmt.Errorf("github: invalid commit sha %q", sha)
	}
	if !validFilePath(path) {
		return File{}, fmt.Errorf("github: invalid file path %q", path)
	}
	if limit <= 0 || limit > MaxFileBytes {
		limit = MaxFileBytes
	}
	body, _, err := c.get(ctx, base+"/contents/"+path, url.Values{"ref": {sha}}, maxContentsBody)
	if err != nil {
		return File{}, err
	}
	return decodeFile(body, path, limit)
}

func decodeFile(body []byte, path string, limit int64) (File, error) {
	if bytes.HasPrefix(bytes.TrimSpace(body), []byte("[")) {
		return File{}, fmt.Errorf("github: %s is a directory", path)
	}
	var w wireContent
	if err := json.Unmarshal(body, &w); err != nil {
		return File{}, errors.New("github: unreadable contents answer")
	}
	switch {
	case w.Type != "file":
		return File{}, fmt.Errorf("github: %s is not a regular file (%q)", path, w.Type)
	case w.Path != path:
		return File{}, errors.New("github: the answer is for another path")
	case w.Size > limit:
		return File{}, fmt.Errorf("%w: %s is %d bytes, limit %d", ErrFileTooLarge, path, w.Size, limit)
	case w.Encoding != "base64":
		return File{}, fmt.Errorf("github: unsupported content encoding %q", w.Encoding)
	}
	content, err := base64.StdEncoding.DecodeString(strings.NewReplacer("\n", "", "\r", "").Replace(w.Content))
	switch {
	case err != nil:
		return File{}, errors.New("github: content is not valid base64")
	case int64(len(content)) > limit:
		return File{}, fmt.Errorf("%w: %s exceeds %d bytes", ErrFileTooLarge, path, limit)
	case int64(len(content)) != w.Size:
		return File{}, errors.New("github: content length differs from the reported size")
	case blobSHA(content) != w.SHA:
		return File{}, errors.New("github: content does not match its blob sha")
	}
	return File{Path: path, BlobSHA: w.SHA, Content: content}, nil
}

// blobSHA is the git blob id of content.
func blobSHA(content []byte) string {
	h := sha1.New() //nolint:gosec // see import
	_, _ = fmt.Fprintf(h, "blob %d\x00", len(content))
	_, _ = h.Write(content)
	return fmt.Sprintf("%x", h.Sum(nil))
}

// validFilePath accepts a clean, relative, slash-separated path: no empty, "."
// or ".." segment, no backslash or control character.
func validFilePath(p string) bool {
	if p == "" || len(p) > 1024 || strings.ContainsRune(p, '\\') {
		return false
	}
	for _, r := range p {
		if unicode.IsControl(r) || r == unicode.ReplacementChar {
			return false
		}
	}
	for _, segment := range strings.Split(p, "/") {
		if segment == "" || segment == "." || segment == ".." {
			return false
		}
	}
	return true
}
