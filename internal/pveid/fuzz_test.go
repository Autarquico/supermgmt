package pveid

import (
	"errors"
	"strings"
	"testing"
)

// fuzzInputLimit is far beyond any pveum answer.
const fuzzInputLimit = 1 << 20

func FuzzParseTokenAdd(f *testing.F) {
	f.Add([]byte(goodTokenAnswer))
	f.Add([]byte(`{"full-tokenid":"sm-ab12@pve!sm","value":"0a1b2c3d-4e5f-6071-8293-a4b5c6d7e8f9"}`))
	f.Add([]byte(`{"full-tokenid":"sm-ab12@pve!sm","value":"x"}{"value":"y"}`))
	f.Add([]byte(`{"value":null,"full-tokenid":""}`))
	f.Add([]byte(``))
	f.Fuzz(func(t *testing.T, in []byte) {
		if len(in) > fuzzInputLimit {
			t.Skip("beyond any pveum answer")
		}
		secret, err := ParseTokenAdd(in, "sm-ab12@pve", "sm")
		if err != nil {
			if !errors.Is(err, ErrUnreadable) || secret != "" || err.Error() != ErrUnreadable.Error() {
				t.Fatalf("refusal must be ErrUnreadable alone: %v", err)
			}
			return
		}
		if !tokenSecretPattern.MatchString(secret.Reveal()) || !strings.Contains(string(in), secret.Reveal()) {
			t.Fatalf("accepted a secret that is not a safe word of the input")
		}
	})
}

func FuzzParsePVEList(f *testing.F) {
	f.Add([]byte(`[{"userid":"sm-ab12@pve"}]`), "userid", "sm-ab12@pve")
	f.Add([]byte(`[{"path":"/","roleid":"R","type":"user","ugid":"u@pve"}]`), "roleid", "R")
	f.Add([]byte(`[{"tokenid":"sm","comment":"supermgmt install ab12"}]`), "tokenid", "sm")
	f.Add([]byte(`{`), "", "")
	f.Fuzz(func(t *testing.T, in []byte, field, want string) {
		if len(in) > fuzzInputLimit {
			t.Skip("beyond any pveum answer")
		}
		if _, err := ParseListed(in, field, want); err != nil && !errors.Is(err, ErrUnreadable) {
			t.Fatalf("ParseListed: %v", err)
		}
		acls, err := ParseACLs(in)
		if err != nil && !errors.Is(err, ErrUnreadable) {
			t.Fatalf("ParseACLs: %v", err)
		}
		for _, a := range acls {
			if (a.User == "") == (a.Token == "") {
				t.Fatalf("an ACL names both or neither: %+v", a)
			}
		}
		if _, err := ParseOwnedToken(in, "sm-ab12@pve", "sm"); err != nil && !errors.Is(err, ErrUnreadable) {
			t.Fatalf("ParseOwnedToken: %v", err)
		}
		if _, owned, err := ParseOwnedUser(in, "sm-ab12@pve"); err != nil && (!errors.Is(err, ErrUnreadable) || owned) {
			t.Fatalf("ParseOwnedUser: %v", err)
		}
		if _, _, err := ParseRolePrivileges(in, "SMAudit-ab12"); err != nil && !errors.Is(err, ErrUnreadable) {
			t.Fatalf("ParseRolePrivileges: %v", err)
		}
	})
}

func FuzzParseCAPEM(f *testing.F) {
	ca := testCA(f)
	f.Add([]byte(ca))
	f.Add([]byte(ca + ca))
	f.Add([]byte("junk\n" + ca))
	f.Add([]byte(strings.Replace(ca, "CERTIFICATE", "PRIVATE KEY", 2)))
	f.Add([]byte(``))
	f.Fuzz(func(t *testing.T, in []byte) {
		if len(in) > fuzzInputLimit {
			t.Skip("beyond any host file")
		}
		cert, canonical, err := ParseCAPEM(in)
		if err != nil {
			if !errors.Is(err, ErrNotACA) || err.Error() != ErrNotACA.Error() || cert != nil || canonical != "" {
				t.Fatalf("refusal must be ErrNotACA alone: %v", err)
			}
			return
		}
		if !cert.IsCA {
			t.Fatal("accepted a certificate that is not a CA")
		}
		again, canonicalAgain, err := ParseCAPEM([]byte(canonical))
		if err != nil || canonicalAgain != canonical || !again.Equal(cert) {
			t.Fatalf("canonical form is not stable: %v", err)
		}
	})
}

func FuzzParseManagerVersion(f *testing.F) {
	f.Add("pve-manager/9.0.3/abcdef (running kernel: 6.14.8-2-pve)\n")
	f.Add("pve-manager/9/x")
	f.Add("pve-manager/9.0.3.1")
	f.Add("")
	f.Fuzz(func(t *testing.T, out string) {
		if len(out) > fuzzInputLimit {
			t.Skip("beyond any pveversion answer")
		}
		version, ok := ParseManagerVersion(out)
		if ok && (version == "" || !strings.Contains(out, "pve-manager/"+version)) {
			t.Fatalf("version %q is not in the answer", version)
		}
	})
}
