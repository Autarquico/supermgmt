package pveid

import (
	"errors"
	"strings"
	"testing"
)

const goodTokenAnswer = `{"full-tokenid":"sm-ab12@pve!sm","info":{"privsep":"1","comment":"c"},"value":"0a1b2c3d-4e5f-6071-8293-a4b5c6d7e8f9"}`

func TestParseTokenAddAcceptsPveumsAnswer(t *testing.T) {
	secret, err := ParseTokenAdd([]byte(goodTokenAnswer), "sm-ab12@pve", "sm")
	if err != nil || secret.Reveal() != "0a1b2c3d-4e5f-6071-8293-a4b5c6d7e8f9" {
		t.Fatalf("secret %v err %v", secret, err)
	}
	if _, err := ParseTokenAdd([]byte(`{"full-tokenid":"sm-ab12@pve!sm","info":{"privsep":1},"value":"0a1b2c3d-4e5f-6071-8293-a4b5c6d7e8f9"}`), "sm-ab12@pve", "sm"); err != nil {
		t.Errorf("an answer without info was refused: %v", err)
	}
}

func TestParseTokenAddRefusesEveryOtherShapeWithoutEchoingIt(t *testing.T) {
	const value = "0a1b2c3d-4e5f-6071-8293-a4b5c6d7e8f9"
	bad := map[string]string{
		"empty":            ``,
		"not json":         `SECRET-` + value,
		"array":            `[` + goodTokenAnswer + `]`,
		"other token":      `{"full-tokenid":"sm-ab12@pve!other","value":"` + value + `"}`,
		"other user":       `{"full-tokenid":"sm-zz@pve!sm","value":"` + value + `"}`,
		"no token id":      `{"value":"` + value + `"}`,
		"no value":         `{"full-tokenid":"sm-ab12@pve!sm"}`,
		"empty value":      `{"full-tokenid":"sm-ab12@pve!sm","value":""}`,
		"short value":      `{"full-tokenid":"sm-ab12@pve!sm","value":"abc"}`,
		"value with space": `{"full-tokenid":"sm-ab12@pve!sm","value":"` + value + ` x"}`,
		"value not string": `{"full-tokenid":"sm-ab12@pve!sm","value":12345678901234567890}`,
		"no info":          `{"full-tokenid":"sm-ab12@pve!sm","value":"` + value + `"}`,
		"null info":        `{"full-tokenid":"sm-ab12@pve!sm","info":null,"value":"` + value + `"}`,
		"scalar info":      `{"full-tokenid":"sm-ab12@pve!sm","info":"1","value":"` + value + `"}`,
		"list info":        `{"full-tokenid":"sm-ab12@pve!sm","info":[],"value":"` + value + `"}`,
		"privsep off":      `{"full-tokenid":"sm-ab12@pve!sm","info":{"privsep":0},"value":"` + value + `"}`,
		"privsep off text": `{"full-tokenid":"sm-ab12@pve!sm","info":{"privsep":"0"},"value":"` + value + `"}`,
		"unknown field":    `{"full-tokenid":"sm-ab12@pve!sm","value":"` + value + `","extra":1}`,
		"trailing object":  goodTokenAnswer + goodTokenAnswer,
		"trailing brace":   goodTokenAnswer + `}`,
		"trailing text":    goodTokenAnswer + ` SECRET`,
	}
	for name, in := range bad {
		secret, err := ParseTokenAdd([]byte(in), "sm-ab12@pve", "sm")
		if !errors.Is(err, ErrUnreadable) || secret != "" {
			t.Errorf("%s: secret %q err %v", name, secret, err)
			continue
		}
		if strings.Contains(err.Error(), value) || strings.Contains(err.Error(), "SECRET") {
			t.Errorf("%s: the error echoes the input: %v", name, err)
		}
	}
}

func TestParseListed(t *testing.T) {
	out := []byte(`[{"userid":"root@pam"},{"userid":"sm-ab12@pve"},{"userid":7}]`)
	if ok, err := ParseListed(out, "userid", "sm-ab12@pve"); !ok || err != nil {
		t.Errorf("ok %v err %v", ok, err)
	}
	if ok, _ := ParseListed(out, "userid", "7"); ok {
		t.Error("a non-string field matched")
	}
	if _, err := ParseListed([]byte(`{"userid":"x"}`), "userid", "x"); !errors.Is(err, ErrUnreadable) {
		t.Errorf("err = %v", err)
	}
}

func TestParseACLsKeepsUserAndTokenEntries(t *testing.T) {
	out := []byte(`[{"path":"/","roleid":"R","type":"user","ugid":"u@pve"},{"path":"/vms","roleid":"R","type":"token","ugid":"u@pve!sm"},{"path":"/","roleid":"R","type":"group","ugid":"g"}]`)
	acls, err := ParseACLs(out)
	if err != nil || len(acls) != 2 || acls[0].User != "u@pve" || acls[1].Token != "u@pve!sm" || acls[1].Path != "/vms" {
		t.Errorf("acls %+v err %v", acls, err)
	}
}

func TestParseOwnedTokenNeedsTheIdentitysComment(t *testing.T) {
	user := User("ab12")
	mine := `[{"tokenid":"sm","comment":"supermgmt install ab12","privsep":1}]`
	foreign := `[{"tokenid":"sm","comment":"made by hand","privsep":1},{"tokenid":"sm"}]`
	if owned, separated, err := ParseOwnedToken([]byte(mine), user, "sm"); !owned || !separated || err != nil {
		t.Errorf("own token: %v %v %v", owned, separated, err)
	}
	if owned, _, _ := ParseOwnedToken([]byte(foreign), user, "sm"); owned {
		t.Error("a foreign token counted as ours")
	}
}

func TestParseOwnedTokenReportsWhetherItIsPrivilegeSeparated(t *testing.T) {
	user := User("ab12")
	for name, row := range map[string]string{
		"off":     `{"tokenid":"sm","comment":"supermgmt install ab12","privsep":0}`,
		"missing": `{"tokenid":"sm","comment":"supermgmt install ab12"}`,
		"text":    `{"tokenid":"sm","comment":"supermgmt install ab12","privsep":"1"}`,
	} {
		owned, separated, err := ParseOwnedToken([]byte("["+row+"]"), user, "sm")
		if !owned || separated || err != nil {
			t.Errorf("%s: owned %v separated %v err %v", name, owned, separated, err)
		}
	}
}
