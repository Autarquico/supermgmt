# M2 manual checks: release key, credential stores, real IdP, real proxy, real VM

What the automated M2 gates cannot show: they ran with a throwaway signing key, fakes for the OS credential tools and an in-process or Dex test identity provider (the Docker end-to-end suite was not part of the code these checks were written against). Run this list by hand before M2 is signed off, fill in the results table at the end, and record the commit (`sm version`) and the environment of each check. A check you skip stays "not verified" in the README and ROADMAP.

Conventions: `$SM` is the built or installed `sm`; a server named `mgmt.example.com` is used in examples.

## 0. Release environment and key (owner only, one time)

Nothing can be installed from a real release until this is done. Everything in [installation.md](../installation.md#release-key-and-custody) assumes it.

1. Generate the key on an offline or trusted machine, **without a passphrase** (the workflows sign non-interactively):
   `ssh-keygen -t ed25519 -N '' -C release@supermgmt -f release_key`
   Record the fingerprint: `ssh-keygen -lf release_key.pub`.
2. In the GitHub repository: Settings, Environments, create **`release`**; add yourself as a **required reviewer**; restrict deployment branches and tags (`main` for `channels.yml`, `v*` for `release.yml`). Add the secret **`SM_RELEASE_SIGNING_KEY`** to that environment only, with the content of `release_key` (the private key, including the `BEGIN`/`END` lines). Do not add it as a repository or organisation secret.
3. Put the public key in both trust blocks, replacing the placeholder comment line between `# BEGIN allowed_signers` and `# END allowed_signers`, in **`install.sh` and `scripts/join.sh`** (they embed it separately; a test keeps their verification functions identical but not their keys):
   `release@supermgmt valid-after="YYYYMMDD",namespaces="supermgmt-release" ssh-ed25519 AAAA...`
   Review the diff of both files before committing: this is the trust root of every install.
4. Publish the fingerprint out-of-band: the project website and the release notes, and in `SECURITY.md` and `docs/installation.md` (replace the `<RELEASE-KEY-FINGERPRINT-NOT-PUBLISHED-YET>` placeholders) at the signed tag. Keep an encrypted offline copy of the private key; losing it means rotating the key (a release signed by the old key announcing the new one).
5. Push a pre-release tag first (for example `v0.1.0-rc.1`; tags with a hyphen publish as pre-releases). Approve the `release` environment run. Expected: the run passes its own `release-check` step, and the release has `sm_*_{linux,darwin}_{amd64,arm64}.tar.gz`, their `.spdx.json`, `checksums.txt` and `.sig`, `install.sh` and `.sig`, `join.sh` and `.sig`.
6. Check the provenance of an archive: `gh attestation verify sm_0.1.0-rc.1_linux_amd64.tar.gz --repo autarquico/supermgmt`. Expected: verified. This is the first time provenance is exercised.
7. Run the `channels` workflow once by hand (`workflow_dispatch`) and approve it. Expected: the `channels` release holds `stable.json` and `beta.json` with `.sig`. Note that the schedule is weekly and **every run waits for your approval**; if you do not approve for 21 days (each pointer is valid for 21 days), channel pointers expire and `latest` installs fail with exit 5 (pinned `SUPERMGMT_VERSION` installs keep working).
8. Review the `workflow-policy` CI job result: no other workflow references environment `release` or the secret.

## 1. `install.sh` with the real key

On a **clean Debian or Ubuntu VM** with systemd, as root (this also covers the VM run that the M2 acceptance criterion defers):

1. Review-first: download `install.sh` and `install.sh.sig` from the release, verify them with an `allowed_signers` file you wrote from the *published* fingerprint, then `SUPERMGMT_VERSION=v0.1.0-rc.1 bash install.sh server --public-url https://mgmt.example.com --tls proxy`. Expected: verified, installed, the unit is active, `/health/ready` answers, a bootstrap code is printed.
2. `curl | bash`: the same on another VM: `curl -fsSL https://raw.githubusercontent.com/autarquico/supermgmt/main/install.sh | bash -s -- server --public-url ...`. Expected: the same result (this path trusts `main`, which the check cannot show).
3. Tamper: download a release archive, flip a byte, serve it from a local mirror (`SUPERMGMT_RELEASE_BASE_URL`). Expected: exit 5, nothing installed.
4. OpenSSH: on a host with `ssh-keygen` older than 8.2 (for example Debian 10), run `install.sh`. Expected: exit 4 with the "OpenSSH 8.2 or newer" message, before any download.
5. `--tls direct` with a real certificate for the host. Expected: starts; `kill -HUP $(pidof sm)` after replacing the certificate picks up the new one without restart.
6. Reboot the VM. Expected: the service comes back; `sm doctor` (as root) is healthy.
7. Run the default mode: `bash install.sh` with no mode, on a headless VM. Expected since M3: `auto` finds no desktop and no Proxmox host, asks on a terminal whether to install the server (yes runs `server`), and without a terminal exits 2 asking for `SUPERMGMT_MODE`.

## 2. First sign-in without OIDC (suspected defect)

On the server from check 1, from your laptop:

```bash
sm profile add prod --url https://mgmt.example.com --use
sm login --bootstrap          # paste the code printed by the installer
```

Expected by the design: you become admin and a session is stored. Suspected: the server answers `display_name is required`, because `sm login --bootstrap` sends only the code while the server needs a name when OIDC is off (`internal/cli/login.go` `bootstrapLogin`, `internal/app/auth.go` `createAdmin`). Record what happens. If it fails, issue a new code (`sudo sm admin bootstrap-code`) and call `POST /api/v1/auth/bootstrap` with `{"code":"...","display_name":"admin"}` to continue, and report the defect.

## 3. macOS Keychain

On macOS, record the version (`sw_vers`). `$SM` is the release build.

1. `printf '%s\n' "$TOKEN" | sm login --token-stdin` with a real API token (from `sm tokens create`). Expected: "credential kept in the macOS keychain".
2. `security find-generic-password -s supermgmt -a prod -w` prints the token. `sm status` (or any command) works without a prompt, or with exactly one Keychain permission prompt that stays allowed after "Always Allow".
3. **`security -i` and stdin.** While check 1 runs, in a second terminal run `while :; do ps -axww -o args= | grep '[s]ecurity'; done`. Expected: the token never appears in any argument list (it travels on stdin). Repeat the store 20 times to catch a short window. Record whether current macOS accepts the `add-generic-password -U` command on stdin in interactive mode at all; the code reads the value back and reports "the keychain did not keep the token" if it did not stick.
4. `sm logout`, then `security find-generic-password -s supermgmt -a prod` should report not found.
5. Run with the keychain locked (lock it in Keychain Access first). Expected: a clear error or the 0600-file fallback with the location printed, never a silent success.

## 4. Linux Secret Service (`secret-tool`)

On a desktop Linux with GNOME Keyring or KeePassXC and `secret-tool` installed (record distribution and keyring):

1. `printf '%s\n' "$TOKEN" | sm login --token-stdin`. Expected: "the desktop secret service (secret-tool)".
2. `secret-tool lookup service supermgmt account prod` prints the token; a new shell finds the credential without prompting again.
3. Headless host (no D-Bus session, no `secret-tool`): expected: "credentials.json (mode 0600; no OS credential store was usable)" in the config directory; `stat -c %a` shows `600`.
4. During the store, `ps -axww` must not show the token (it is stdin to `secret-tool store`).

## 5. Real OIDC provider

Pick the IdP you will actually use (Google, Okta, Entra ID, Keycloak, a production Dex). Record product and version. Dex is the only provider exercised so far.

1. Register a confidential client. Redirect URI `http://127.0.0.1:<port>/callback`. Decide whether the IdP accepts variable loopback ports; if not, register one fixed port and use `sm login --callback-port <port>`.
2. Enable OIDC following [operations.md](../operations.md#enabling-oidc-on-a-fresh-server): import `auth/oidc-client-secret`, set `auth.oidc.*`, restart.
3. `sm login`. Expected: browser opens, you sign in, the CLI reports your identity. Check the audit events (`sm events`) for the login, and that `allowed_domains` refuses an account from another domain and an account with an unverified email.
4. If the IdP serves its token or JWKS endpoint from another origin: expected failure `PROVIDER_ERROR` until that origin is listed in `auth.oidc.allowed_endpoint_origins`; then success.
5. Device grant: `sm login --device`. Expected: a code and a URL; sign in on a phone; the CLI completes. **With Dex:** look at the URL the browser shows after entering the code and note whether it contains `client_secret=` (the documented leak); if it does, that client's secret is exposed to whoever signed in this way.
6. Give the new identity a role (`sudo sm admin grant <identity-id> admin` on the server) and confirm it can run a write; confirm an identity with no role gets `POLICY_DENIED`.
7. Stop the IdP and confirm the server keeps running and existing sessions keep working; only new logins fail.
8. Session end: after `security.session_ttl`, the stored session is refused with an authentication error and `sm login` works again.

## 6. Behind a real reverse proxy

nginx, Caddy or Traefik in front of `--tls proxy` (record which and its version). `server.trusted_proxies` set to the proxy's address.

1. The proxy sets `X-Forwarded-Proto: https` and `X-Forwarded-For`. `sm login` and a normal command work over `https://mgmt.example.com`.
2. Remove the proxy's `X-Forwarded-Proto`. Expected: every request is `400` ("must be https").
3. From a host that is **not** a trusted proxy, send `X-Forwarded-For: 203.0.113.9` straight to the listener (open it temporarily to a test host). Expected: the header is ignored; the audit trail and rate limits use the real peer address.
4. `curl` the listener from the server's own loopback with a valid token but without forwarding headers while `trusted_proxies` does not include loopback. Expected: no special trust; the token still has to be valid.
5. Event stream: `sm tui` or `curl -N -H "Authorization: Bearer $TOKEN" https://mgmt.example.com/api/v1/events/stream`. Expected: heartbeat comments every 15 seconds and events arrive without proxy buffering delay. If events arrive in bursts, disable response buffering for that path in the proxy.
6. Join with a source restriction: `sm enrollments create --source-cidr <your node's public CIDR>`, then `sm join` from that node and from another network. Expected: accepted from the first, refused from the second. This is the check that the proxy delivers the right client address.
7. Rate limit: 20 failed `POST /api/v1/auth/bootstrap` calls in a minute from one address. Expected: 429 with `Retry-After` after the burst.

## 7. Backup and restore on real machines

1. On the VM from check 1: `sm backup create`; `sm backup list` shows an archive and its key id; copy the archive off the machine.
2. `sudo systemctl stop supermgmt`; `sudo -u supermgmt sm secrets export-key <kek-id> --offline --out /root/kek.smkey` (passphrase of 12 or more characters). Keep both away from the archive.
3. On a second clean VM: `install.sh restore --archive FILE --key-export /root/kek.smkey --public-url ...`. Expected: restored, the service is up **in restore hold** (writes return `RESTORE_HOLD`), no bootstrap code printed.
4. `sudo sm admin bootstrap-code` (accepted during hold), sign in, `sm doctor`, `sm jobs list` (interrupted jobs), copy `/var/lib/supermgmt/restored-config/config.yaml` over `/etc/supermgmt/config.yaml` if wanted, `sudo sm admin restore-complete`. Expected: writes work again; the nodes are reachable (the instance SSH key came back with the archive and the key).
5. Kill the restore at a random moment (`kill -9`) a few times on a copy; start the service or re-run the restore. Expected: it finishes or refuses with instructions, never a half-state.
6. Single-operator approval: with `security.allow_self_approval: false` and one admin, run `sm secrets rotate-master-key --yes`. Expected: the job waits (`sm jobs list`); only a second identity or `allow_self_approval: true` lets it proceed.

## 8. Optional: Cloudflare Tunnel

Only if you will use it. Follow [cloudflare.md](../cloudflare.md) with a real tunnel. Record whether `X-Forwarded-Proto` is `https` at the origin, what `X-Forwarded-For` holds for the client address, and whether Access in front of the hostname blocks `sm` (expected, since `sm` cannot add Access headers). Update the guide with what you find.

## Results

Fill in after running; attach notes for any failure.

| Check | Date | Environment (OS, versions, IdP, proxy) | Pass / fail / skipped | Notes |
|---|---|---|---|---|
| 0 Release environment and key |  |  |  |  |
| 1 install.sh with the real key (VM) |  |  |  |  |
| 2 First sign-in without OIDC |  |  |  |  |
| 3 macOS Keychain |  |  |  |  |
| 4 Linux secret-tool |  |  |  |  |
| 5 Real OIDC provider |  |  |  |  |
| 6 Real reverse proxy |  |  |  |  |
| 7 Backup and restore on real machines |  |  |  |  |
| 8 Cloudflare Tunnel (optional) |  |  |  |  |
