# Manual checks: Cloudflare Tunnel with a real account

**Status: NOT RUN. Nothing on this page has been done.** The tunnel feature was verified only against a hand-written Cloudflare API fake (`internal/providers/cloudflare/cffake`) and a fake `cloudflared` that forwards to a test SSH server. Those prove SuperMgmt's state machine, its ordering, its secret handling and its seams; they do not prove what Cloudflare or the real `cloudflared` do. The feature stays **experimental** until every row below is done and the results are written in [Project status](../project-status.md). Where a row says "record", write what you saw, even when it differs from the expectation, and fix the code or the docs.

Use a throwaway Cloudflare account (or a zone you can wreck), a SuperMgmt instance in local or server mode, and two lab nodes: one **Debian 13** and one **Ubuntu 24.04**, both set up already (`sm nodes setup`), reachable directly, with your own SSH key authorised for an admin account. You need a second Cloudflare-visible identity that is **not** in `owner_emails` (a second email address you can receive mail on).

Conventions: `$ACCOUNT` is the account ID, `$ZONE` the zone, `$NODE` the node name, `$HOST` is `ssh-$NODE.$ZONE`, `$INSTANCE` the SuperMgmt instance ID, `$NODEID` the node ID.

## 1. Permissions and the API token

| # | Check | Expected by the code |
|---|---|---|
| 1.1 | In the dashboard, create an API token with the four permissions in [Cloudflare](../cloudflare.md#what-you-need). Write down the exact label of each as the dashboard shows it | The labels match the page. Record any difference and correct the page |
| 1.2 | Store it (`sm secrets import --name cloudflare/api-token`), add the `cloudflare:` block, run `sm doctor` | `cloudflare_api_token` ok ("valid and active"), `cloudflare_api_reads` ok listing tunnels, access.apps, access.policies, access.service_tokens, zone and dns, `cloudflare_edit_rights` warn "not verifiable" |
| 1.3 | Remove permissions one at a time (each in turn), run `sm doctor` and then `sm nodes setup $NODE --tunnel` | Doctor names the read that fails. Record which permission each API call really needs; in particular whether the zone lookup by name needs a permission beyond the four, and whether Zone: DNS: Edit alone is enough for the DNS calls |
| 1.4 | Scope the token's zone permission to a different zone | The setup job fails at the DNS step, after the Access application exists and before any DNS record, and says so. Remove the leftovers with `sm nodes tunnel disable` or by hand |

## 2. The package repository on the nodes

| # | Check | Expected |
|---|---|---|
| 2.1 | Out of band, fetch Cloudflare's current package key from their documentation and run `gpg --show-keys --with-fingerprint` on it | The fingerprint is `CC94B39C77AE7342A68B89628A682D308D4E5E73`, the one pinned in `internal/runtimes/systemd/cloudflare_pin.go`. Record the key's expiry date. If it differs, stop: setup must fail closed, and the pin must be updated by a person who has verified the new key |
| 2.2 | On each node, `curl -fsSI https://pkg.cloudflare.com/cloudflared/dists/any/InRelease` | 200. The source line setup writes uses the suite `any` and component `main`; confirm Debian 13 and Ubuntu 24.04 both resolve packages from it |
| 2.3 | After provisioning (section 3), compare `/etc/apt/keyrings/cloudflare-main.gpg` with the key from 2.1, and read `/etc/apt/sources.list.d/cloudflared.list` | The same key; the single line `deb [signed-by=/etc/apt/keyrings/cloudflare-main.gpg] https://pkg.cloudflare.com/cloudflared any main` |
| 2.4 | `apt-cache policy cloudflared` and `cloudflared --version` on the node | Installed from `pkg.cloudflare.com`. Record the version; the design was written against 2026.10.x |

## 3. Provisioning

| # | Check | Expected |
|---|---|---|
| 3.1 | `sm nodes setup $NODE --tunnel` on the Debian node, approve it | The job completes; `sm nodes get $NODE` shows transport `cloudflare` and hostname `$HOST` |
| 3.2 | In the dashboard, list what exists | A tunnel `sm-$INSTANCE-$NODEID` (healthy, one connector), its public hostname `$HOST` to `ssh://localhost:22`, an Access application `supermgmt $INSTANCE $NODEID` on `$HOST` with a Service Auth policy and an Allow policy, a proxied DNS record `$HOST` with comment `supermgmt:$INSTANCE:$NODEID`, a service token `supermgmt-$INSTANCE` |
| 3.3 | Record the Allow policy's include rule | Emails from `owner_emails`, restricted to the identity providers in `access_identity_providers` (or any, with one-time PIN when empty). Record how Cloudflare shows it |
| 3.4 | On the node, `systemctl status supermgmt-cloudflared`, `ls -l /etc/supermgmt/cloudflared/token`, `cat /etc/systemd/system/supermgmt-cloudflared.service` | Active; token owned by root, mode 0600; the unit holds `--token-file` and no token text |
| 3.5 | Block the node's SSH port to the control plane (firewall), then run `sm nodes probe $NODE`, read logs of a service and restart a harmless unit | All work through the tunnel with the direct path closed |
| 3.6 | Repeat 3.1 to 3.5 on the Ubuntu node | Same results |
| 3.7 | Run `sm nodes setup $NODE --tunnel` again | A no-op: no duplicate object in the dashboard, no restart of a healthy service |
| 3.8 | While the setup is running, watch the zone's DNS records | The record appears only after the Access application exists |

## 4. Service-token admission

| # | Check | Expected |
|---|---|---|
| 4.1 | From the control plane host: `curl -sI -H "CF-Access-Client-Id: <id>" -H "CF-Access-Client-Secret: <secret>" https://$HOST/` (read the pair from the secret store with your own means, never paste it in a shared place) | No redirect to `*.cloudflareaccess.com`. Record the status code Cloudflare returns for an admitted request to an SSH-only application |
| 4.2 | The same without the headers | A redirect (302) to the Access login |
| 4.3 | In the dashboard, remove the service token from the Service Auth policy and run `sm nodes probe $NODE` | The probe fails with "Cloudflare Access did not admit the service token", **no browser opens** on the control plane host, and no `cloudflared` process is left behind (`ps`) |
| 4.4 | Restore the policy by running `sm nodes setup $NODE --tunnel` | The policy is repaired; the probe works again |
| 4.5 | With the daemon host's `PATH` containing a fake `open` or `xdg-open` that touches a marker file, repeat 4.3 | The marker file is never created |
| 4.6 | Confirm the spawned child's environment: while a probe runs, `ps eww` on the child, or a recording wrapper at `/usr/local/bin/cloudflared` | Only `TUNNEL_SERVICE_TOKEN_ID`, `TUNNEL_SERVICE_TOKEN_SECRET` and `HOME`; arguments exactly `access ssh --hostname $HOST`; no log file; no debug level |

## 5. Owners and non-owners

| # | Check | Expected |
|---|---|---|
| 5.1 | As an owner, install `cloudflared` on your laptop and run `sm ssh $NODE` | A browser (or one-time PIN) login, then a shell on the node. The host key is checked against the pinned one |
| 5.2 | Log in to Access as the second identity (not in `owner_emails`) and run `sm ssh $NODE` | Access denies; no shell |
| 5.3 | As the owner, with your key removed from the admin account's `authorized_keys` | The tunnel admits you; ssh refuses authentication. Admission is not an SSH login |
| 5.4 | Move `cloudflared` away on your laptop and run `sm ssh $NODE` | A clear error telling you to install it; no fallback |
| 5.5 | Change the node's host key (reinstall `sshd` keys) and probe | Refused as a host key mismatch; nothing repinned |

## 6. Secrets in the wild

| # | Check | Expected |
|---|---|---|
| 6.1 | On the node, `journalctl -u supermgmt-cloudflared --no-pager` after a restart, at the default log level | No tunnel credential, no token text. This is the open question from the source reading: record what `cloudflared tunnel run` logs |
| 6.2 | `grep -r` the token, the service-token secret and the API token over: the node's `/etc`, `/var/log`, `ps` output taken during setup, the control plane's logs, the audit events, the plan JSON of each job, and a decompressed `sm backup` archive | None found in plaintext |
| 6.3 | `sm nodes setup $NODE --tunnel` with a deliberately wrong API token | The error names the failing step and contains no token |

## 7. Teardown

| # | Check | Expected |
|---|---|---|
| 7.1 | With the direct path open again, `sm nodes tunnel disable $NODE`, approve it | The transport reads `direct`; the service and files are gone from the node; the package and source file are removed only if setup installed them |
| 7.2 | In the dashboard | The DNS record and ingress are gone, then the Access application, then the tunnel; the service token and the two policies remain |
| 7.3 | Run `sm nodes tunnel disable $NODE` while the direct path is blocked | Refused before anything changes |
| 7.4 | Interrupt a disable halfway (kill the daemon), restart it and run the command again | It resumes and completes; nothing is left behind |

## 8. Rotation

| # | Check | Expected |
|---|---|---|
| 8.1 | With two tunnel nodes, loop `sm nodes probe` on both and run `sm cloudflare rotate-access-token` | Probes keep succeeding throughout |
| 8.2 | In the dashboard | One service token remains, the Service Auth policy lists only the new one, the old one is deleted |
| 8.3 | Create a service token by hand with the same name prefix, then rotate | Record how the job reacts; it must not delete a token it did not create |

## 9. Backup and restore

| # | Check | Expected |
|---|---|---|
| 9.1 | Back up an instance with a tunnel node, restore it on a second machine (the procedure in [Operations](../operations.md)), and before `sm admin restore-complete` try `sm nodes tunnel disable $NODE` | Refused with `RESTORE_HOLD`; nothing changes in Cloudflare |
| 9.2 | Delete the tunnel in the dashboard, then `sudo sm admin restore-complete` | The audit trail shows `cloudflare.reconcile.missing` for the tunnel and `cloudflare.reconcile.completed`; no object was created or deleted by the reconcile itself |
| 9.3 | `sm nodes setup $NODE --tunnel` on the restored instance | The vanished objects are recreated and the node verifies |
| 9.4 | Run the restored copy and the original against the same account, then rotate on one of them | Record what happens; this is documented as unsupported |

## Result

Fill in per row: the date, the SuperMgmt version, the `cloudflared` version and the outcome. A row whose expectation failed is a defect or a documentation error: open an issue and do not move the claim in [Project status](../project-status.md) from "tested against fakes" until it is closed.
