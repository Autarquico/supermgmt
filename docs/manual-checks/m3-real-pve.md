# M3 manual checks: a real Proxmox VE 9.x host

**Status: DEFERRED. Nothing on this page has been run.** Every Proxmox interaction in M3 was verified against fakes: a fake HTTP API (`internal/providers/proxmox/pvefake`), fake `pct`/`pveam`/`pvesm`/`pvesh`/`pveum` commands in the installer tests, and a simulated Proxmox host in the end-to-end tests (`TestM3_Appliance*`, CI job `e2e-appliance`, where each container is a Docker container). The fakes were written from the Proxmox documentation, not recorded from a host ([test/fixtures/pve/PROVENANCE.md](../../test/fixtures/pve/PROVENANCE.md)), so every row of [compatibility.md](../compatibility.md) is "not verified" in its real-host column until this list runs. "Proxmox auto-LXC install works" (SPEC Appendix E) stays unchecked until sections 1 to 6 pass.

Run it on a **lab** Proxmox VE 9.x host (amd64; a nested VM is fine), not on a production cluster: section 5 creates and destroys containers and Proxmox users. Record the Proxmox version (`pveversion -v`), the `sm version` commit and the date of each check. Fill in the results table at the end; a skipped check stays "not verified" in the README and ROADMAP. Where a check says the **fake needs fixing**, change the fake and the matrix row, not the expectation.

Conventions: `$NODE` is the Proxmox node name, `$ST` a storage with `rootdir`, `$TST` one with `vztmpl`, `$VMID` a free VMID. Commands run as root on the Proxmox host unless noted.

## 0. Prepare

1. Build or download `sm` for linux/amd64 and copy it to the host. Use one guest of each kind as a test subject: a stopped QEMU VM and a running LXC that you can lose, on this node; if the lab has a second cluster node, one more guest there.
2. Keep a second terminal on the host for `pvesh`/`pveum` read-backs.

## 1. Host CLI output (read only)

These feed the parsers in `internal/installer/pve.go`. For each, compare the real output with what the parser expects and note any difference.

| # | Command | Expected by the code | Matrix row |
|---|---|---|---|
| 1.1 | `pveversion` | One line starting `pve-manager/9.x.y/...` | `pveversion` |
| 1.2 | `pct list` (with one locked guest, for example during a backup or `pct snapshot`) | Header `VMID Status [Lock] Name`; the Lock column is blank when unlocked, so the column count differs per row | `pct list` columns |
| 1.3 | `pvesm status --output-format json` | JSON rows with `storage`, `type`, `content` (a comma-separated string) and `active` (`1`, `true` or their quoted forms) | `pvesm status` JSON |
| 1.4 | `pvesh get /nodes/$NODE/network --type any_bridge --output-format json` | Rows with the bridge in `iface` and its host address in `address`; `$NODE` equals `hostname -s`, which the installer uses as the node name | bridge discovery |
| 1.5 | `pvesh get /cluster/nextid --vmid $USED` and `--vmid $FREE` | A VMID in use: non-zero exit. A free one: exit 0. (The installer uses the exit code, not the text.) | free-VMID probe |
| 1.6 | `pveam update`, `pveam available --section system \| grep debian-13`, `pveam list $TST` | A template named exactly `debian-13-standard_<version>_amd64.tar.zst`; the installer chooses the highest version | template pattern, `pveam` |
| 1.7 | `pveum user list --output-format json`, `pveum role list ...`, `pveum acl list ...` | Rows with `userid`, `roleid`, and for ACLs `path`, `roleid`, `ugid`, `type` (`user` or `token`) | `pveum` rows |

## 2. HTTP API shapes

Create a throwaway token first (section 3 shows the privileges), then call the API with `curl --cacert /etc/pve/pve-root-ca.pem -H "Authorization: PVEAPIToken=$TOKEN" https://$HOST:8006/api2/json/...`, or run `sm providers check --offline <name>` for the end-to-end result.

| # | Check | Expected by the code |
|---|---|---|
| 2.1 | `GET /nodes/$NODE/tasks?limit=5&start=0` | Newest first; a top-level `total` field; paging with `start` reads to the end. If `total` is absent or means something else, **the fake needs fixing** and the read-to-the-end loop in `internal/providers/proxmox` must be re-checked. |
| 2.2 | `GET /nodes/$NODE/tasks/<upid>/status` for a running task (start a long `vzdump` or a template download) | `status: running` and **no** `exitstatus`. For an ended task: `status: stopped` plus `exitstatus` (`OK` on success). |
| 2.3 | `timeout` parameter: `POST /nodes/$NODE/{qemu,lxc}/<id>/status/{start,stop,shutdown,reboot}` with `timeout=240` | The code sends it on `shutdown` and `reboot` only. Check which of the eight verb and guest-type combinations accept it, and which reject it with a 400. Record the result in the matrix row "`timeout` parameter". |
| 2.4 | The task type names of each of those eight POSTs (in the returned UPID) | `qmstart`, `qmstop`, `qmshutdown`, `qmreboot`, `vzstart`, `vzstop`, `vzshutdown`, `vzreboot`. Correlation depends on these exactly. |
| 2.5 | UPID format | `UPID:<node>:<pid>:<pstart>:<starttime>:<type>:<id>:<user>:`, with the token user as `user@realm!tokenid`. Check the user field for a token-started task. |
| 2.6 | Error documents | 400 bad parameter, 401 bad token, 403 missing privilege, 500 failed precondition, 501 unknown endpoint, as in the matrix. |
| 2.7 | A guest migrated to another node: POST a power verb to the **old** node | The code treats a 4xx/5xx with a PVE error body as a definite rejection when the guest "does not exist" on that node. Record the exact status and text (the fake's text is an approximation). Then POST to the new node. |
| 2.8 | `GET /cluster/resources` with the token | Nodes, guests and storages limited to what the token may audit; guest rows have `maxcpu`, `maxmem`, `maxdisk`, `template`, `status`, and `pool` where set. |

## 3. Permissions and the deeper-ACL rule

The central assumption of the privilege design (ADR-0023). Use a throwaway user, token and roles, then remove them.

```bash
pveum user add sm-check@pve
pveum role add SMCheckAudit --privs "VM.Audit,Sys.Audit,Datastore.Audit,Pool.Audit"
pveum role add SMCheckPower --privs "VM.Audit,VM.PowerMgmt"
pveum user token add sm-check@pve t --privsep 1 --output-format json    # keep the secret
pveum acl modify / --roles SMCheckAudit --users sm-check@pve
pveum acl modify / --roles SMCheckAudit --tokens 'sm-check@pve!t'
```

For each case, read `GET /access/permissions` as the token (and `pveum user permissions 'sm-check@pve!t'`) and `GET /cluster/resources`, and write down what each path returns.

| # | Setup | Expected by the code |
|---|---|---|
| 3.1 | Only the `/` grant above | Guests visible; `VM.PowerMgmt` absent everywhere. |
| 3.2 | Add `SMCheckPower` on `/vms` for the user and the token | `VM.PowerMgmt` on `/vms/<id>`; `VM.Audit` still present there. |
| 3.3 | Replace the `/vms` role by a role **without** `VM.Audit` (for example `PVEVMUser`-like with only `VM.PowerMgmt`) | A deeper ACL replaces the inherited role: guests vanish from `/cluster/resources`, `VM.Audit` is missing on `/vms/<id>`. This is why `SMPower-<id>` repeats `VM.Audit`. If Proxmox instead merges them, the repeat is harmless but the matrix and ADR-0023 text must change. |
| 3.4 | Grant on `/vms/<id>` with `--propagate 0` | Applies to that path only; `/access/permissions` lists it without descendants. |
| 3.5 | A grant whose value is `0` or a path that appears with an empty map | How `/access/permissions` encodes a 0-valued, non-propagating grant (the code treats a listed ancestor as authoritative, `decodePerms`). Record the exact JSON. If the value semantics differ, **the fake and `decodePerms` need fixing**. |
| 3.6 | Token privilege separation | With `--privsep 1` the token's rights are the intersection with the user's: remove a privilege from the user only and confirm the token loses it. |
| 3.7 | Revoke the `/` ACL for the token while `sm` is syncing (section 6) | Guests become `inaccessible` after the next sync (not `absent`), capabilities are dropped, rows stay. Restore the ACL and see them return. |

Clean up: `pveum user token remove`, `pveum acl delete`, `pveum role delete`, `pveum user delete`.

## 4. Container behaviour

On a scratch container created by hand with the same options the installer uses (`internal/installer/pve.go`, `TestPVE_CreateArgvIsTheFrozenShape`):

```bash
pct create $VMID $TST:vztmpl/debian-13-standard_<ver>_amd64.tar.zst --hostname t --cores 2 --memory 2048 --swap 512 \
  --rootfs $ST:16 --net0 name=eth0,bridge=vmbr0,ip=dhcp --unprivileged 1 --features nesting=0,keyctl=0 \
  --onboot 1 --tags supermgmt --description "supermgmt install test"
```

| # | Check | Expected |
|---|---|---|
| 4.1 | The create above is accepted by PVE 9 | Exit 0. Note any option PVE 9 rejects or renames. |
| 4.2 | `pct config $VMID` | Shows `unprivileged: 1`, `features: nesting=0,keyctl=0`, `tags: supermgmt`, the description, no `mpN`, no `lxc.*`. The installer reads these back and rolls back on any mismatch; a different format breaks the readback. |
| 4.3 | `pct start $VMID`, then `pct exec $VMID -- /usr/bin/hostname -I` | A non-loopback IPv4 address within 120 s (DHCP). |
| 4.4 | `pct exec $VMID -- /usr/bin/false; echo $?` and a command that exits 3 | The exit code passes through (1 and 3). The installer relies on it (`providers check` exit 8, `test -x`). |
| 4.5 | `pct exec $VMID -- runuser -u root -- /usr/bin/id` in the Debian 13 template | `runuser` exists there. If not, the offline steps cannot run as `supermgmt` and the installer needs another mechanism. |
| 4.6 | `pct push $VMID /tmp/x /tmp/x --user root --group root --perms 0755` | Accepted. Then `pct push` a file into a directory owned by an unprivileged-mapped user with `--user <name> --group <name> --perms 0600`. Expected: owner and mode as given. If the uid mapping makes `--user` ineffective, the installer falls back to `chown`/`chmod` in the container; confirm the fallback works, and record which path ran. |
| 4.7 | `pct exec $VMID -- stat -f -c %T /run` | `tmpfs`. A stop and start leaves `/run` empty. |
| 4.8 | `pct stop $VMID`, `pct destroy $VMID` | Succeed; `pct config` then fails. |

## 5. Appliance install on the real host

Use a fresh lab host state (no previous SuperMgmt appliance) and a Proxmox CA as installed by default.

| # | Check | Expected |
|---|---|---|
| 5.1 | `./sm install proxmox-lxc` with no configuration | The plan names the detected storage, bridge, template and the endpoint `https://<bridge address>:8006`; it proceeds, prints the address, CA fingerprint, CA and bootstrap code. Note the duration, whether the template was downloaded, and any prompt that was needed. |
| 5.2 | The Proxmox endpoint address detected from the bridge | Reachable from the container, and the served certificate (the default `pve-ssl.pem`) chains to `/etc/pve/pve-root-ca.pem`, with the detected address among its names. If the SAN does not cover the address, step "endpoint trust" fails with exit 8; record the message and set `SUPERMGMT_PVE_ENDPOINT` to the host name. |
| 5.3 | Custom or ACME certificate on the Proxmox host | Without `SUPERMGMT_PVE_CA_FILE` the trust check refuses (exit 8) before any token exists, and nothing is left behind. With the right CA it passes. |
| 5.4 | Proxmox firewall blocking 8006 from the container | Exit 8 with the port-8006 hint; full rollback (check `pct list`, `pveum user list`, `pveum role list`, `pveum acl list`, `/var/tmp`). |
| 5.5 | `pveum user list`, `role list`, `acl list`, `user token list` after install | Exactly `sm-<id>@pve`, `SMAudit-<id>`, `SMPower-<id>`, token `sm`, ACLs on `/` and `/vms` for the user and the token; nothing else changed. |
| 5.6 | Inside the container: `ls -l /run/supermgmt-bootstrap`, `systemctl is-enabled supermgmt`, file owners under `/var/lib/supermgmt`, `grep -r` for the token secret in `/var/lib`, `/etc`, the host's `/var/tmp` and `journalctl` | Directory gone, unit enabled and active, data owned by `supermgmt`, the secret appears nowhere. |
| 5.7 | From your workstation: `sm profile add ... --ca-file`, `sm login --bootstrap`, `sm providers list`, `sm nodes list --tree` | Signed in; provider `ok`; the lab node, its guests and storages appear as discovered, with CPU, memory and disk. |
| 5.8 | Rollback at the container step: make `pct create` fail, for example by creating a guest with the planned VMID between the plan and the create | Exit non-zero, a clean host, the pre-existing guest untouched. |
| 5.9 | Rollback after the token exists: kill the installer (`kill -9`) between the token and the import, then rerun `sm install proxmox-lxc` on a terminal | The journal is found, the rerun offers to roll back, and afterwards no user, role, ACL, token, container or `/var/tmp/supermgmt-installer-*` directory remains. |
| 5.10 | Failure after the token import (for example stop the container just before the service starts) | Rolled back, or kept with exit 7 and a precise list; never a half-state without a message. |
| 5.11 | A second install while the first appliance exists | A different VMID, a different install id, separate identities; the first is untouched. |
| 5.12 | Change the container's DHCP lease (restart it so it gets another address) | The appliance certificate names the install-time address, so `sm` clients fail verification; record the error and confirm that a reserved lease avoids it. |

## 6. Operate

With the appliance from section 5 and a lab guest:

| # | Check | Expected |
|---|---|---|
| 6.1 | `sm nodes power <lxc-guest> start`, `shutdown`, `reboot` with `--wait` | Each job succeeds; the Proxmox task log shows one task per call; the guest state follows. |
| 6.2 | `sm nodes power <guest> stop --wait` | The CLI shows high risk; the job waits for approval; after `sm jobs approve ...` the guest stops. |
| 6.3 | Power on a QEMU VM (`start`, `shutdown`) | As 6.1. |
| 6.4 | `SUPERMGMT_PVE_POWER=0` install | No `SMPower-<id>`; guests are discovered; the power capability is not advertised. Record what `sm nodes power` says. |
| 6.5 | Interrupt a power job: cut the container's network just after submitting `reboot` on a long task, or kill the daemon after the POST | The job is `interrupted`, not retried; once the task is visible it is correlated and settled, or held with a clear message. Count the tasks in the Proxmox task list: one. |
| 6.6 | Delete a guest in Proxmox; revoke the audit ACL on another | The first becomes `absent`, the second `inaccessible`; the rows stay. |
| 6.7 | Rename a guest in Proxmox with a plan pending | The plan is stale after the next sync. |
| 6.8 | `sm providers refresh pve` repeatedly | Rate limited after 3 quick calls (HTTP 429, error code `TIMEOUT`). |
| 6.9 | `sm doctor` on the appliance | The `providers` check reports `ok`. |

## 7. Upgrade and uninstall on the real host

| # | Check | Expected |
|---|---|---|
| 7.1 | Build a newer `sm` (any version bump), then on the host `./sm-new install upgrade` | Delegates into the appliance after the record and tag check; backup taken; version changes; data intact; `upgrade.json` gone. |
| 7.2 | The same with two appliances installed | Refused without `--vmid`; works with it; the other appliance is untouched. |
| 7.3 | Upgrade from the previous milestone's build (a server installed by M2) to this one | The backup has the old schema; the migration to 4 runs; the service is ready. |
| 7.4 | Kill the upgrade at each phase (`kill -9` during stop, backup, swap, start) and rerun | It converges; `/usr/local/bin/sm` exists at every moment. |
| 7.5 | Break the new binary's start (a binary that exits 1) | The old binary is back (schema unchanged); exit 9. |
| 7.6 | `./sm install uninstall --vmid <id>` | The container is stopped, the software removed inside it, the container, data, record and Proxmox identities remain. |
| 7.7 | `./sm install uninstall --vmid <id> --purge-data` | Asks for the VMID; the container is destroyed; only that install's user, token, roles and ACLs are removed; the other appliance's identities and the template remain; the record is gone. |

## Results

| Check | Result (pass / fail / skipped) | Host (PVE version) | `sm version` | Date | Notes |
|---|---|---|---|---|---|
| 1.1 to 1.7 | | | | | |
| 2.1 to 2.8 | | | | | |
| 3.1 to 3.7 | | | | | |
| 4.1 to 4.8 | | | | | |
| 5.1 to 5.12 | | | | | |
| 6.1 to 6.9 | | | | | |
| 7.1 to 7.7 | | | | | |

When a check changes an assumption, update in the same change: the fake, its row in [compatibility.md](../compatibility.md) (fake-verified becomes real-verified, or the row is corrected), [PROVENANCE.md](../../test/fixtures/pve/PROVENANCE.md), and the README and ROADMAP status.
