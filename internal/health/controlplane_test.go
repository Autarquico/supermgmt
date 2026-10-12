package health

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/autarquico/supermgmt/internal/netguard"
)

const controlPlaneBody = "secret-response-body"

// controlPlaneClient reaches srv for every address the filter lets through.
func controlPlaneClient(srv *httptest.Server) *http.Client {
	dial := func(network, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(context.Background(), network, srv.Listener.Addr().String())
	}
	allow := netguard.Allow{AllowHTTP: true, PrivateCIDRs: []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")}}
	return netguard.NewClient(allow, nil, 2*time.Second, 64<<10, netguard.WithTestDialer(dial))
}

func controlPlaneCheck(url string) Check {
	return Check{Origin: OriginControlPlane, Type: TypeHTTP, Scope: ScopeControlPlane, URL: url, Timeout: 2 * time.Second}
}

func controlPlaneServer(t *testing.T, status int) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/health", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(status)
		_, _ = w.Write([]byte(controlPlaneBody))
	})
	mux.HandleFunc("/moved", func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, "/health", http.StatusFound) })
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

func TestControlPlane_SSRFTable(t *testing.T) {
	tests := []struct {
		name        string
		url         string
		wantHealthy bool
	}{
		{"private address in allowlist", "http://10.0.0.7/health", true},
		{"private address outside allowlist", "http://192.168.1.10/health", false},
		{"loopback", "http://127.0.0.1/health", false},
		{"ipv6 loopback", "http://[::1]/health", false},
		{"cloud metadata", "http://169.254.169.254/health", false},
		{"link-local", "http://169.254.1.1/health", false},
		{"unspecified", "http://0.0.0.0/health", false},
		{"ipv4-mapped loopback", "http://[::ffff:127.0.0.1]/health", false},
		{"decimal loopback", "http://2130706433/health", false},
	}
	srv := controlPlaneServer(t, http.StatusOK)
	hc := controlPlaneClient(srv)
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			res, err := ControlPlane(context.Background(), hc, controlPlaneCheck(tt.url))
			if err != nil || res.Healthy != tt.wantHealthy {
				t.Fatalf("result = %+v, %v; want healthy=%v", res, err, tt.wantHealthy)
			}
			if !tt.wantHealthy && res.Detail == "" {
				t.Fatal("unhealthy result has no detail")
			}
		})
	}
}

func TestControlPlane_JudgesStatusAndNeverLeaksTheBody(t *testing.T) {
	tests := []struct {
		name        string
		path        string
		status      int
		wantHealthy bool
		wantStatus  int
	}{
		{"200", "/health", http.StatusOK, true, 200},
		{"204", "/health", http.StatusNoContent, true, 204},
		{"500", "/health", http.StatusInternalServerError, false, 500},
		{"redirect is never followed", "/moved", http.StatusOK, false, 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv := controlPlaneServer(t, tt.status)
			res, err := ControlPlane(context.Background(), controlPlaneClient(srv), controlPlaneCheck("http://10.0.0.7"+tt.path))
			if err != nil || res.Healthy != tt.wantHealthy || res.Status != tt.wantStatus {
				t.Fatalf("result = %+v, %v", res, err)
			}
			if strings.Contains(res.Detail, controlPlaneBody) {
				t.Fatalf("detail leaks the body: %q", res.Detail)
			}
		})
	}
}

func TestControlPlane_TimeoutIsUnhealthy(t *testing.T) {
	slow := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) { <-r.Context().Done() }))
	t.Cleanup(slow.Close)
	c := controlPlaneCheck("http://10.0.0.7/health")
	c.Timeout = time.Second
	res, err := ControlPlane(context.Background(), controlPlaneClient(slow), c)
	if err != nil || res.Healthy {
		t.Fatalf("result = %+v, %v", res, err)
	}
}

func TestControlPlane_MalformedCheckIsAnError(t *testing.T) {
	hc := controlPlaneClient(controlPlaneServer(t, http.StatusOK))
	nodeScope := controlPlaneCheck("http://10.0.0.7/")
	nodeScope.Scope = ScopeNode
	for name, c := range map[string]Check{
		"node scope":  nodeScope,
		"userinfo":    controlPlaneCheck("http://u:p@10.0.0.7/"),
		"query":       controlPlaneCheck("http://10.0.0.7/?a=1"),
		"file scheme": controlPlaneCheck("file:///etc/passwd"),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := ControlPlane(context.Background(), hc, c); err == nil {
				t.Fatal("expected an error")
			}
		})
	}
}
