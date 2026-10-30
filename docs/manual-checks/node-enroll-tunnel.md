# Manual checks: adding a node through Cloudflare Tunnel, on a real account

**Status: NOT RUN.** Enrollment through the tunnel was verified only against fakes: a hand-written Cloudflare API fake, a fake `cloudflared` and an in-process SSH server. The feature stays **experimental** until every row below is done and the results are written in [Project status](../project-status.md). Where a row says "record", write what you saw, even when it differs from the expectation, and fix the code or the docs.

You need a Cloudflare account with the `cloudflare:` block from [Cloudflare](../cloudflare.md) configured, a SuperMgmt instance in local mode on a laptop with `cloudflared`, and a fresh Debian 13 or Ubuntu 24.04 VPS whose firewall drops every inbound connection (SSH included) and allows outbound HTTPS.

## 1. The enrollment

| # | Check | Expected |
|---|---|---|
| 1.1 | `sm nodes add --name vps1 --tunnel`, approve | It prints the line for the node and, separately, the tunnel credential. In the dashboard: a tunnel, an Access application and a DNS record `ssh-vps1.<zone>`. Record the order in the audit log |
| 1.2 | `sm nodes list` | `vps1` is listed under open enrollments with its expiry, not as a node |
| 1.3 | Run the line on the VPS with `sudo`, paste the credential at the prompt | Nothing echoes. It ends with `host key: SHA256:…`. `ps`, the shell history and `journalctl` show no credential. Record the `cloudflared` version |
| 1.4 | Compare the fingerprint `sm` shows with the one the VPS printed, answer yes | `vps1` is saved with `transport: cloudflare`. `sm nodes get vps1` shows the pinned key |
| 1.5 | On the VPS, `ss -tn` while `sm` probes the node | Only outbound connections to Cloudflare. No inbound connection ever reached port 22 |
| 1.6 | `cat /var/lib/supermgmt/.ssh/authorized_keys`, `systemctl status supermgmt-cloudflared.service` | One `restrict` line with the instance comment. The unit is active, sandboxed, and its credential file is mode 0600 |

## 2. Failure paths

| # | Check | Expected |
|---|---|---|
| 2.1 | Start an enrollment and never run the line; wait past `--expires-in 5m` | The DNS record, the Access application and the tunnel are gone. The instance's service token and policies remain. Record how long the cleanup took |
| 2.2 | Start one and `--cancel` it after the line ran | Same cleanup; `cloudflared` on the VPS keeps retrying a deleted tunnel. Record its log |
| 2.3 | Answer no at the fingerprint prompt | `SSH_HOST_KEY_MISMATCH`, the objects are removed, no node is saved |
| 2.4 | Kill the daemon while it waits for the node, start it again | The enrollment resumes and completes. No duplicate object in the dashboard |
| 2.5 | Run the line on a Debian 12 host | It stops before installing anything, naming the distribution |
| 2.6 | `sm nodes tunnel disable vps1` | Refused before any change: the node has no direct path |

## 3. Credentials

| # | Check | Expected |
|---|---|---|
| 3.1 | After 1.4, `sm nodes add --tunnel --name vps1 --show-token` | Refused: the enrollment is finished and the credential deleted from the store |
| 3.2 | Search `sm events --json`, the daemon log and the backup archive for the credential | Absent |
