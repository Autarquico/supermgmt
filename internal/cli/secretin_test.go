package cli

import (
	"strings"
	"testing"
)

func TestEmptyStandardInputIsSaidToBeEmpty(t *testing.T) {
	_, err := readSecretFromStream(strings.NewReader(""), secretInput{limit: 16})
	if err == nil || !strings.Contains(err.Error(), "standard input was empty") {
		t.Errorf("got %v", err)
	}
	if _, err := readSecretFromStream(strings.NewReader("x\n"), secretInput{limit: 16}); err != nil {
		t.Errorf("a value must still be read: %v", err)
	}
}
