// Package plan defines the canonical action plan (spec Appendix C, version 3)
// and its hash: SHA-256 over the RFC 8785 (JCS) serialization of the
// normalized plan. Approvals bind to that hash (spec §11.4), so every rule
// here is a security property: one plan has exactly one byte representation.
package plan

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"

	"github.com/autarquico/supermgmt/internal/domain"
	smerr "github.com/autarquico/supermgmt/internal/errors"
)

// Version is the only plan version this package hashes.
const Version = 3

// Plan lists every input that can change what executes. Slices are sorted by
// Normalize rules except Steps, which keeps execution order. Nullable fields
// are pointers and are always serialized: absent optional values are null,
// never omitted, so no field carries omitempty.
type Plan struct {
	Version    int64            `json:"version"`
	Action     string           `json:"action"`
	Actor      string           `json:"actor"`
	Targets    []Target         `json:"targets"`
	Inputs     []Input          `json:"inputs"`
	Content    Content          `json:"content"`
	SubActions []SubAction      `json:"sub_actions"`
	Parameters map[string]any   `json:"parameters"`
	Steps      []string         `json:"steps"`
	Risk       domain.RiskClass `json:"risk"`
}

// Target is a resource the action changes.
type Target struct {
	Type         string `json:"type"`
	ID           string `json:"id"`
	SpecRevision *int64 `json:"spec_revision"`
}

// Input is a configured resource the execution reads. Which optional fields
// apply depends on Type (a secret has Version, a node has Endpoint and a host
// key fingerprint); the rest are null.
type Input struct {
	Type                string    `json:"type"`
	ID                  string    `json:"id"`
	SpecRevision        *int64    `json:"spec_revision"`
	Version             *int64    `json:"version"`
	Endpoint            *Endpoint `json:"endpoint"`
	HostPublicKeySHA256 *string   `json:"host_public_key_sha256"`
}

// Endpoint is the management endpoint pinned at plan time (spec §6.4).
type Endpoint struct {
	Address string `json:"address"`
	Port    int64  `json:"port"`
	User    string `json:"user"`
}

// Content holds the content hashes of materialized inputs.
type Content struct {
	CommitSHA            *string         `json:"commit_sha"`
	ManifestBlobSHA      *string         `json:"manifest_blob_sha"`
	ComposeHash          *string         `json:"compose_hash"`
	Images               []Image         `json:"images"`
	ExceptionsHash       *string         `json:"exceptions_hash"`
	HealthHash           *string         `json:"health_hash"`
	DeploymentPolicyHash *string         `json:"deployment_policy_hash"`
	HostPorts            []string        `json:"host_ports"`
	RollbackTarget       *RollbackTarget `json:"rollback_target"`
	SecretBindings       []SecretBinding `json:"secret_bindings"`
}

// Image binds a service to an image reference.
type Image struct {
	Service string `json:"service"`
	Ref     string `json:"ref"`
	Binding string `json:"binding"`
}

// RollbackTarget names the deployment a rollback returns to.
type RollbackTarget struct {
	DeploymentID string `json:"deployment_id"`
	ComposeHash  string `json:"compose_hash"`
}

// SecretBinding references a secret version; never its value.
type SecretBinding struct {
	Service  string `json:"service"`
	EnvName  string `json:"env_name"`
	SecretID string `json:"secret_id"`
	Version  int64  `json:"version"`
}

// SubAction is an additional action the plan performs on a target.
type SubAction struct {
	Action string    `json:"action"`
	Target SubTarget `json:"target"`
}

// SubTarget identifies the resource of a sub-action.
type SubTarget struct {
	Type string `json:"type"`
	ID   string `json:"id"`
}

// Parse decodes a plan from JSON. Numbers are kept exact (never via float64),
// so a float anywhere in the document is rejected later by Hash and Canonical.
// Unknown fields and trailing data are errors.
func Parse(data []byte) (*Plan, error) {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	dec.DisallowUnknownFields()
	var p Plan
	if err := dec.Decode(&p); err != nil {
		return nil, smerr.Wrap(err, smerr.CodeInvalidArgument, "", "plan is not valid JSON for version 3")
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return nil, invalid("trailing data after plan")
	}
	return &p, nil
}

func invalid(format string, args ...any) error {
	return smerr.New(smerr.CodeInvalidArgument, "", "plan: "+fmt.Sprintf(format, args...))
}
