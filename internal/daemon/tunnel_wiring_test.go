package daemon

import "testing"

const cloudflareBlock = `cloudflare:
  account_id: 0123456789abcdef0123456789abcdef
  zone: example.test
  owner_emails: [owner@example.test]
`

// The cloudflare transport and the tunnel jobs exist only when the
// configuration has a cloudflare: block; without one nothing about them is built.
func TestTheCloudflareTransportIsWiredOnlyWithACloudflareBlock(t *testing.T) {
	without := m4Builder(t, "")
	without.useCloudflareTransport()
	if without.tunnel != nil || without.tunnelOptions() != nil {
		t.Error("a dialler or tunnel options exist without a cloudflare: block")
	}

	with := m4Builder(t, cloudflareBlock)
	with.useCloudflareTransport()
	t.Cleanup(with.closeTransport)
	if with.tunnel == nil {
		t.Fatal("no cloudflare dialler with a cloudflare: block")
	}
	options := with.tunnelOptions()
	if options == nil || options.Config.AccessTokenRef != "secret://cloudflare/access-service-token" {
		t.Errorf("tunnel options = %+v, want the configured block with its default references", options)
	}
	with.closeTransport()
	with.closeTransport() // idempotent: shutdown after a failed assembly closes it once more
}
