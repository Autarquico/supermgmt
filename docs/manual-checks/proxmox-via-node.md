# Manual checks: Proxmox through its SSH node, on a real host

**Status: NOT RUN.** Proxmox through a node was verified only against fakes: an in-process SSH relay to `pvefake` and fake PVE tools. The feature stays **experimental** until every row below is done and the results are written in [Project status](../project-status.md). Where a row says "record", write what you saw, even when it differs from the expectation, and fix the code or the docs.

You need a Proxmox VE 9 host that you can SSH into as root, and a SuperMgmt instance in local mode. For section 4 you also need the `cloudflare:` block from [Cloudflare](../cloudflare.md).

## 1. Setup detects the host

| # | Check | Expected |
|---|---|---|
| 1.1 | `sm nodes add --name pve1 --host <ip> --admin-user root`, then `sm nodes setup pve1 --proxmox`, then approve | The job succeeds and prints the three-line provider block |
| 1.2 | On the host, `command -v socat` before and after | If it was missing, setup installed it from the Debian repositories. Record the package version |
| 1.3 | On the host, `pveum user list`, `pveum role list`, `pveum user token list <user>` | One user and its roles, named with the instance ID and carrying the owner comment. One privilege-separated token. Nothing else changed |
| 1.4 | `openssl x509 -in /etc/pve/local/pve-ssl.pem -noout -ext subjectAltName` | The name setup recorded (`sm nodes get pve1`) is one of these SANs. Record which one |
| 1.5 | On a PVE 8 host, or on a Debian node without PVE | Setup fails with `CAPABILITY_UNAVAILABLE`. No PVE identity is created and `socat` is not installed |

## 2. The provider through the node

| # | Check | Expected |
|---|---|---|
| 2.1 | Add the printed block to the config and restart the daemon. Run `sm providers list` and `sm nodes list` | The provider is healthy, and the host's guests are listed |
| 2.2 | While it syncs, run `ss -tn` on the host | No connection to `:8006` from outside the host. Connections to `127.0.0.1:8006` come from `socat` |
| 2.3 | Start and then stop a test guest from SuperMgmt | Both power actions succeed. Record the PVE task IDs |
| 2.4 | `journalctl` on the host and `sm events` | The token secret appears in neither |

## 3. Forwarding stays closed

| # | Check | Expected |
|---|---|---|
| 3.1 | On the host, `cat /var/lib/supermgmt/.ssh/authorized_keys` | One line, starting with `restrict ` and with no `port-forwarding` or `permitopen`. Record the OpenSSH version (`ssh -V`) |

## 4. Through Cloudflare

| # | Check | Expected |
|---|---|---|
| 4.1 | `sm nodes setup pve1 --tunnel` | The node switches to `cloudflare`. The provider keeps syncing |
| 4.2 | Block the host's port 22 and port 8006 from your network, then sync from another network | The sync still works |
| 4.3 | On the host, remove the token (`pveum user token remove <user> <token>`), then run `sm nodes setup pve1 --proxmox` again | The provider fails until setup runs. Setup creates the token again and the provider recovers at the next sync |
