package policy

import (
	"bytes"
	"errors"

	smerr "github.com/autarquico/supermgmt/internal/errors"
	"github.com/autarquico/supermgmt/internal/yamlstrict"
)

// Parse decodes and validates a policy file. Decoding is strict: unknown
// fields, duplicate keys and multiple YAML documents are errors.
func Parse(data []byte) (*Policy, error) {
	p, _, err := ParseWithWarnings(data)
	return p, err
}

// ParseWithWarnings is Parse that also reports the retired actions the file
// names, once per action.
func ParseWithWarnings(data []byte) (*Policy, []Warning, error) {
	doc, err := decode(data)
	if err != nil {
		return nil, nil, err
	}
	return build(doc)
}

// New validates doc and returns the policy built from it.
func New(doc Document) (*Policy, error) {
	p, _, err := build(doc)
	return p, err
}

func build(doc Document) (*Policy, []Warning, error) {
	if err := validate(doc); err != nil {
		return nil, nil, err
	}
	live, warnings := withoutRetired(doc)
	return &Policy{rules: live.Rules}, warnings, nil
}

func decode(data []byte) (Document, error) {
	var doc Document
	switch err := yamlstrict.Decode(bytes.NewReader(data), &doc); {
	case errors.Is(err, yamlstrict.ErrEmpty):
		return Document{}, invalidPolicy("policy file is empty", nil)
	case err != nil:
		return Document{}, invalidPolicy("cannot decode policy", err)
	}
	return doc, nil
}

func invalidPolicy(msg string, cause error) error {
	return smerr.Wrap(cause, smerr.CodeInvalidArgument, "", msg)
}
