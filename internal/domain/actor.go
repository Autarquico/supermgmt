package domain

import "time"

// CredentialContext is the credential a request authenticated with; plans and
// jobs persist it and it is re-checked at claim (spec §11.1).
type CredentialContext struct {
	Kind      CredentialKind
	ID        string
	Scopes    []string
	ExpiresAt *time.Time
}

// Actor is the single identity behind a request.
type Actor struct {
	ID         ID
	Type       ActorType
	Roles      []string
	Credential CredentialContext
}

// ResourceRef points at one resource.
type ResourceRef struct {
	Type ResourceType
	ID   ID
}
