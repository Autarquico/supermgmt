package oidc

import "testing"

// FuzzParseHTTPS: an accepted URL is https, has a host and carries no userinfo.
func FuzzParseHTTPS(f *testing.F) {
	f.Add("https://idp.example.com/realms/x")
	f.Add("http://idp.example.com")
	f.Add("https://user:pw@idp.example.com")
	f.Add("https://@idp.example.com")
	f.Add("https:///path")
	f.Add("https://[::1]:8443/")
	f.Add("HTTPS://IDP.EXAMPLE.COM")
	f.Add("//idp.example.com")
	f.Add("https://idp.example.com/%zz")
	f.Add("")

	f.Fuzz(func(t *testing.T, raw string) {
		u, err := parseHTTPS(raw)
		if err != nil {
			if u != nil {
				t.Fatalf("%q: error with a non-nil URL", raw)
			}
			return
		}
		if u.Scheme != "https" || u.Hostname() == "" || u.User != nil {
			t.Fatalf("%q accepted as %+v", raw, u)
		}
	})
}
