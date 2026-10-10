package policy

import (
	"bytes"
	"errors"
	"io"

	"go.yaml.in/yaml/v3"

	smerr "github.com/autarquico/supermgmt/internal/errors"
)

// Parse decodes and validates a policy file. Decoding is strict: unknown
// fields, duplicate keys and multiple YAML documents are errors.
func Parse(data []byte) (*Policy, error) {
	doc, err := decode(data)
	if err != nil {
		return nil, err
	}
	return New(doc)
}

// New validates doc and returns the policy built from it.
func New(doc Document) (*Policy, error) {
	if err := validate(doc); err != nil {
		return nil, err
	}
	return &Policy{rules: doc.Rules}, nil
}

func decode(data []byte) (Document, error) {
	var doc Document
	decoder := yaml.NewDecoder(bytes.NewReader(data))
	decoder.KnownFields(true)
	if err := decoder.Decode(&doc); err != nil {
		if errors.Is(err, io.EOF) {
			return Document{}, invalidPolicy("policy file is empty", nil)
		}
		return Document{}, invalidPolicy("cannot decode policy", err)
	}
	var extra yaml.Node
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return Document{}, invalidPolicy("policy file must contain exactly one YAML document", err)
	}
	return doc, nil
}

func invalidPolicy(msg string, cause error) error {
	return smerr.Wrap(cause, smerr.CodeInvalidArgument, "", msg)
}
