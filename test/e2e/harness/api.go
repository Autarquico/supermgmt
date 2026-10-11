//go:build e2e

package harness

import "github.com/autarquico/supermgmt/internal/client"

// Typed returns the repository's own HTTPS client for this server, signed with token.
func (s *Server) Typed(token string) *client.Client {
	s.t.Helper()
	c, err := client.NewRemote(client.Remote{URL: s.URL, CAFile: s.CAFile, Token: token}, client.Options{})
	if err != nil {
		s.t.Fatal(err)
	}
	return c
}
