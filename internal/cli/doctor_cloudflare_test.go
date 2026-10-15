package cli

import (
	"os"
	"strings"
	"testing"
)

const cloudflareBlock = `
cloudflare:
  account_id: 0123456789abcdef0123456789abcdef
  zone: example.com
  owner_emails: [owner@example.com]
`

func TestOfflineDoctorShowsTheCloudflareChecksOnlyWithTheBlock(t *testing.T) {
	cloudflareChecks := []string{"cloudflare_cloudflared", "cloudflare_tunnel_operations"}
	tests := []struct {
		name  string
		block string
		want  bool
	}{
		{"with the block", cloudflareBlock, true},
		{"without the block", "", false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			s := newSandbox(t)
			s.migratedDatabase(t)
			config, err := os.ReadFile(s.configFile)
			if err != nil {
				t.Fatal(err)
			}
			writeFile(t, s.configFile, string(config)+tc.block)

			r := s.run("doctor", "--offline", "--json")

			for _, name := range cloudflareChecks {
				c, found := doctorCheckNamed(t, r, name)
				if found != tc.want {
					t.Errorf("%s found = %v, want %v (%+v)", name, found, tc.want, c)
				}
			}
			if tc.want {
				if c, _ := doctorCheckNamed(t, r, "cloudflare_tunnel_operations"); c.Status != statusOK || !strings.Contains(c.Detail, "none") {
					t.Errorf("operations check = %+v, want ok with none in progress", c)
				}
				for _, online := range []string{"cloudflare_api_token", "cloudflare_service_token"} {
					if _, found := doctorCheckNamed(t, r, online); found {
						t.Errorf("%s reported offline", online)
					}
				}
			}
		})
	}
}
