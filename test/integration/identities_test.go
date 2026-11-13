package integration

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/autarquico/supermgmt/internal/api/wire"
)

func (s *recoveryServer) identityCall(method, path, token string) (int, []byte) {
	s.t.Helper()
	return s.do(http.DefaultClient, method, s.api+path, token, "")
}

func TestARecoveredAdminDisablesTheLostAdminAndItsTokenStopsWorking(t *testing.T) {
	s, identityA, tokenA := newServerWithAdmin(t)
	identityB, tokenB := mustExchange(t, s, s.mustIssue(recoverBody), "Admin B")

	t.Run("the new admin sees the old admin's tokens", func(t *testing.T) {
		status, payload := s.identityCall(http.MethodGet, wire.Path(wire.PathIdentityTokens, identityA), tokenB)
		if status != http.StatusOK {
			t.Fatalf("status %d: %s", status, payload)
		}
		var reply struct{ Data wire.Page[wire.Token] }
		if err := json.Unmarshal(payload, &reply); err != nil || len(reply.Data.Items) != 1 || reply.Data.Items[0].IdentityID.String() != identityA {
			t.Fatalf("tokens = %s (%v), want the old admin's bootstrap token", payload, err)
		}
	})

	t.Run("disabling the old admin makes its token UNAUTHENTICATED and leaves the new admin working", func(t *testing.T) {
		if got := s.listNodes(tokenA); got != http.StatusOK {
			t.Fatalf("the old token before the disable: status %d", got)
		}
		status, payload := s.identityCall(http.MethodPost, wire.Path(wire.PathIdentityDisable, identityA), tokenB)
		if status != http.StatusOK {
			t.Fatalf("disable: status %d: %s", status, payload)
		}
		if got := s.listNodes(tokenA); got != http.StatusUnauthorized {
			t.Errorf("the old token after the disable: status %d, want %d", got, http.StatusUnauthorized)
		}
		if got := s.listNodes(tokenB); got != http.StatusOK {
			t.Errorf("the new admin's token after the disable: status %d", got)
		}
	})

	t.Run("the identity list shows the old admin disabled and without roles", func(t *testing.T) {
		status, payload := s.identityCall(http.MethodGet, wire.PathIdentities, tokenB)
		if status != http.StatusOK {
			t.Fatalf("status %d: %s", status, payload)
		}
		var reply struct{ Data wire.Page[wire.Identity] }
		if err := json.Unmarshal(payload, &reply); err != nil {
			t.Fatal(err)
		}
		byID := map[string]wire.Identity{}
		for _, i := range reply.Data.Items {
			byID[i.ID.String()] = i
		}
		if a := byID[identityA]; a.DisabledAt == nil || len(a.Roles) != 0 {
			t.Errorf("old admin = %+v, want disabled and without roles", a)
		}
		if b := byID[identityB]; b.DisabledAt != nil || len(b.Roles) != 1 || b.Roles[0] != "admin" {
			t.Errorf("new admin = %+v, want enabled with the admin role", b)
		}
	})

	t.Run("the last enabled admin cannot disable itself", func(t *testing.T) {
		status, _ := s.identityCall(http.MethodPost, wire.Path(wire.PathIdentityDisable, identityB), tokenB)
		if status != http.StatusConflict {
			t.Errorf("status %d, want %d", status, http.StatusConflict)
		}
		if got := s.listNodes(tokenB); got != http.StatusOK {
			t.Errorf("the last admin's token after a refused self-disable: status %d", got)
		}
	})
}
