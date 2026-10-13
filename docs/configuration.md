# Configuration

SuperMgmt reads one YAML file. The schema is defined in SPEC §8 (`docs/spec/SUPERMGMT-SPEC.md`) and implemented in `internal/config`. A complete example is [`examples/config.yaml`](../examples/config.yaml); a policy example is [`examples/policies.yaml`](../examples/policies.yaml).

> **Status:** pre-alpha. The loader and validator back `sm config validate` and `sm doctor --offline`; the local daemon (M1) and `sm server` (M2) read the file at start. Accepting a key does not mean its feature is implemented: [Which keys are read](#which-keys-are-read) lists what is wired. Proxmox providers (M3) and GitHub providers and `github.*` (M4) are read by the daemon; MCP: M5.

## File location

Pass `--config <path>`. The default locations (SPEC §8.1) are:

| Mode | Config file | Database |
|---|---|---|
| Linux server | `/etc/supermgmt/config.yaml` | `/var/lib/supermgmt/supermgmt.db` |
| Linux, local user | `$XDG_CONFIG_HOME/supermgmt/config.yaml` (default `~/.config/supermgmt/`) | `$XDG_DATA_HOME/supermgmt/supermgmt.db` (default `~/.local/share/supermgmt/`) |
| macOS, local user | `~/Library/Application Support/SuperMgmt/config.yaml`, unless `XDG_*` variables are set | `~/Library/Application Support/SuperMgmt/supermgmt.db` |

Paths that you do not set (`instance.data_dir`, `storage.sqlite.path`, `security.keys_dir`, `ssh.known_hosts_file`, `backup.directory`) are derived from the mode: the server locations above for `instance.mode: server`, the local-user locations otherwise. `security.keys_dir` defaults to `<instance.data_dir>/secrets/keys` and holds the KEK files; back them up separately from the database ([security.md](security.md#secrets-and-the-instance-ssh-identity-m1)).

The daemon socket is `$XDG_RUNTIME_DIR/supermgmt/sm.sock` on Linux when that variable is set, otherwise `<state dir>/run/sm.sock` (state dir `$XDG_STATE_HOME/supermgmt`, default `~/.local/state/supermgmt`; on macOS `~/Library/Application Support/SuperMgmt/state`). `daemon.socket` overrides it. The autostarted daemon writes its log to `daemon.log` in the state directory.

## Which keys are read

### Local daemon and CLI (M1)

- `instance.*`, `daemon.*` (`socket`, `idle_exit`, `resident`), `storage.sqlite.*`
- `security.keys_dir`, `security.policy_file`, `security.approval_ttl`, `security.allow_self_approval`
- `ssh.*` timeouts and pool limits: `connect_timeout`, `command_timeout`, `keepalive_interval`, `max_dials_in_flight`, `max_connections`, `max_sessions_per_connection`, `idle_connection_ttl`
- `refresh.*`, `jobs.*`, `server.shutdown_timeout`
- `environments` and SSH `providers`, applied when the daemon starts
- Proxmox `providers` (M3), applied when the daemon starts and then synced every `sync_interval`; see [providers.md](providers.md#proxmox)
- GitHub `providers` (M4), applied when the daemon starts; see [GitHub](#github)
- `github.oidc_audience`, `github.ci_poll_initial`, `github.ci_poll_max`, `github.ci_timeout`, and `health.allowed_private_cidrs` (control-plane health checks only); environment keys `require_provenance` and `allow_automatic_rollback` (`internal/daemon/assemble.go`, `internal/app/staticconfig.go`)

### Server (M2), read by `sm server`

- `server.listen`, `server.tls.*`, `server.trusted_proxies`, `server.admin_socket`, `server.request_timeout`, `server.shutdown_timeout`; see [Server](#server-transport-and-tls)
- `auth.bootstrap.code_ttl`, `security.session_ttl`
- `auth.oidc.*` except `redirect_url`; see [OIDC](#oidc)
- `backup.schedule`, `backup.retention`, `backup.directory`; see [Backup](#backup)
- `security.redact_command_output` (when false, raw log output is kept)
- `outbound.proxy`, used only for requests to the identity provider
- `ssh.known_hosts_file`: only as the file that goes into a backup archive (and is restored to `<data_dir>/known_hosts`). The pinned host key in the database is still the only trust anchor ([ADR-0015](adr/0015-ssh-transport-and-command-templates.md)).

Reading was checked by searching the code for each key; a key not listed has no reader outside the config package.

### Validated but not read

- `ssh.host_key_policy` (must be `strict`) and `ssh.logs_mode`: the log mode of a node comes from the `logs_mode` parameter of its `node.setup` plan.
- `ui.theme`, `server.public_url` (only the installer and the default of `github.oidc_audience` use it), `auth.oidc.redirect_url` (reserved for a web callback; the CLI uses a loopback redirect)
- `mcp.*`

## How a value is resolved

In order, later steps win:

1. built-in defaults;
2. the YAML file;
3. `SUPERMGMT_*` environment overrides (table below);
4. mode-dependent defaults for anything still unset;
5. validation.

## Strict validation

Unknown fields fail validation, so a typo is an error rather than a silently ignored setting. Validation reports every problem at once, each located by its YAML path, and `sm config validate` exits with code 2 on invalid input (it reports the problems first). Decoding rejects duplicate keys, YAML aliases, anchors and merge keys as well as unknown fields. Examples of what is checked: `version` must be 1; `instance.mode` is `local` or `server`; in server mode, `server.tls.mode: direct` needs a certificate and key, and `server.tls.mode: proxy` needs non-empty `server.trusted_proxies` and a loopback or Unix-socket listener; durations and the worker and connection counts must be positive; `ssh.host_key_policy` must be `strict`; `jobs.reconcile_grace` must be at least `ssh.connect_timeout` + `ssh.command_timeout` + 5s; `mcp.remote_enabled` needs complete `mcp.oauth` settings; environments and providers must be well formed.

Secrets are never written inline. Credential references are URIs from a closed set; any other scheme fails validation:

| Reference | Meaning |
|---|---|
| `secret://<path>` | encrypted secret in the SuperMgmt store. `secret://ssh/default` is the instance SSH identity; other names are stored with `sm secrets import --name <path>` ([operations.md](operations.md#key-management)). `secret://<path>@<n>` pins version `n`. The key that reads such a name in M2 is `auth.oidc.client_secret_ref`; whether provider `credential_ref` values other than `secret://ssh/default` resolve for SSH nodes is not verified |
| `ssh-agent://default` | the daemon user's `$SSH_AUTH_SOCK`; local mode only, rejected in server mode. In M1 it serves `admin_user` only |
| `file://<abs-path>` | key file at an absolute path; discouraged, supported for migration |

## Environment overrides

Every scalar setting and every string list can be overridden with an environment variable named `SUPERMGMT_` plus the upper-cased YAML path with dots replaced by underscores (`server.listen` becomes `SUPERMGMT_SERVER_LISTEN`). Lists are comma-separated. Durations use Go syntax (`30s`, `10m`). Lists of structures, `environments` and `providers`, can only be set in the file.

Variables that start with `SUPERMGMT_` but are neither overrides nor installer variables are reported as warnings and ignored. The installer's own variables (`SUPERMGMT_VERSION`, `SUPERMGMT_CHANNEL`, `SUPERMGMT_MODE`, `SUPERMGMT_INSTALL_DIR`, `SUPERMGMT_CONFIG_DIR`, `SUPERMGMT_DATA_DIR`, `SUPERMGMT_NONINTERACTIVE`, `SUPERMGMT_YES`, `SUPERMGMT_RELEASE_BASE_URL`) are not configuration overrides ([installation.md](installation.md)).

The table below is generated from the schema by `make generate` (`go generate ./...`). Do not edit it by hand; CI fails on drift.

<!-- BEGIN GENERATED ENV TABLE -->
| Variable | YAML path | Type |
|---|---|---|
| `SUPERMGMT_INSTANCE_NAME` | `instance.name` | string |
| `SUPERMGMT_INSTANCE_MODE` | `instance.mode` | string |
| `SUPERMGMT_INSTANCE_DATA_DIR` | `instance.data_dir` | string |
| `SUPERMGMT_SERVER_LISTEN` | `server.listen` | string |
| `SUPERMGMT_SERVER_PUBLIC_URL` | `server.public_url` | string |
| `SUPERMGMT_SERVER_TLS_MODE` | `server.tls.mode` | string |
| `SUPERMGMT_SERVER_TLS_CERT_FILE` | `server.tls.cert_file` | string |
| `SUPERMGMT_SERVER_TLS_KEY_FILE` | `server.tls.key_file` | string |
| `SUPERMGMT_SERVER_TRUSTED_PROXIES` | `server.trusted_proxies` | list (comma-separated) |
| `SUPERMGMT_SERVER_ADMIN_SOCKET` | `server.admin_socket` | string |
| `SUPERMGMT_SERVER_REQUEST_TIMEOUT` | `server.request_timeout` | duration |
| `SUPERMGMT_SERVER_SHUTDOWN_TIMEOUT` | `server.shutdown_timeout` | duration |
| `SUPERMGMT_DAEMON_SOCKET` | `daemon.socket` | string |
| `SUPERMGMT_DAEMON_IDLE_EXIT` | `daemon.idle_exit` | duration |
| `SUPERMGMT_DAEMON_RESIDENT` | `daemon.resident` | bool |
| `SUPERMGMT_UI_THEME` | `ui.theme` | string |
| `SUPERMGMT_REFRESH_FOCUSED_INTERVAL` | `refresh.focused_interval` | duration |
| `SUPERMGMT_REFRESH_INVENTORY_INTERVAL` | `refresh.inventory_interval` | duration |
| `SUPERMGMT_REFRESH_METRICS_INTERVAL` | `refresh.metrics_interval` | duration |
| `SUPERMGMT_REFRESH_DISCOVERY_INTERVAL` | `refresh.discovery_interval` | duration |
| `SUPERMGMT_STORAGE_SQLITE_PATH` | `storage.sqlite.path` | string |
| `SUPERMGMT_STORAGE_SQLITE_BUSY_TIMEOUT` | `storage.sqlite.busy_timeout` | duration |
| `SUPERMGMT_STORAGE_SQLITE_WAL` | `storage.sqlite.wal` | bool |
| `SUPERMGMT_SECURITY_KEYS_DIR` | `security.keys_dir` | string |
| `SUPERMGMT_SECURITY_POLICY_FILE` | `security.policy_file` | string |
| `SUPERMGMT_SECURITY_SESSION_TTL` | `security.session_ttl` | duration |
| `SUPERMGMT_SECURITY_APPROVAL_TTL` | `security.approval_ttl` | duration |
| `SUPERMGMT_SECURITY_ALLOW_SELF_APPROVAL` | `security.allow_self_approval` | bool |
| `SUPERMGMT_SECURITY_REDACT_COMMAND_OUTPUT` | `security.redact_command_output` | bool |
| `SUPERMGMT_AUTH_BOOTSTRAP_CODE_TTL` | `auth.bootstrap.code_ttl` | duration |
| `SUPERMGMT_AUTH_OIDC_ENABLED` | `auth.oidc.enabled` | bool |
| `SUPERMGMT_AUTH_OIDC_ISSUER` | `auth.oidc.issuer` | string |
| `SUPERMGMT_AUTH_OIDC_CLIENT_ID` | `auth.oidc.client_id` | string |
| `SUPERMGMT_AUTH_OIDC_CLIENT_SECRET_REF` | `auth.oidc.client_secret_ref` | string |
| `SUPERMGMT_AUTH_OIDC_REDIRECT_URL` | `auth.oidc.redirect_url` | string |
| `SUPERMGMT_AUTH_OIDC_ALLOWED_DOMAINS` | `auth.oidc.allowed_domains` | list (comma-separated) |
| `SUPERMGMT_AUTH_OIDC_ALLOWED_ENDPOINT_ORIGINS` | `auth.oidc.allowed_endpoint_origins` | list (comma-separated) |
| `SUPERMGMT_SSH_CONNECT_TIMEOUT` | `ssh.connect_timeout` | duration |
| `SUPERMGMT_SSH_COMMAND_TIMEOUT` | `ssh.command_timeout` | duration |
| `SUPERMGMT_SSH_KEEPALIVE_INTERVAL` | `ssh.keepalive_interval` | duration |
| `SUPERMGMT_SSH_MAX_DIALS_IN_FLIGHT` | `ssh.max_dials_in_flight` | int |
| `SUPERMGMT_SSH_MAX_CONNECTIONS` | `ssh.max_connections` | int |
| `SUPERMGMT_SSH_MAX_SESSIONS_PER_CONNECTION` | `ssh.max_sessions_per_connection` | int |
| `SUPERMGMT_SSH_IDLE_CONNECTION_TTL` | `ssh.idle_connection_ttl` | duration |
| `SUPERMGMT_SSH_KNOWN_HOSTS_FILE` | `ssh.known_hosts_file` | string |
| `SUPERMGMT_SSH_HOST_KEY_POLICY` | `ssh.host_key_policy` | string |
| `SUPERMGMT_SSH_LOGS_MODE` | `ssh.logs_mode` | string |
| `SUPERMGMT_JOBS_WORKERS` | `jobs.workers` | int |
| `SUPERMGMT_JOBS_LEASE` | `jobs.lease` | duration |
| `SUPERMGMT_JOBS_HEARTBEAT` | `jobs.heartbeat` | duration |
| `SUPERMGMT_JOBS_RECONCILE_GRACE` | `jobs.reconcile_grace` | duration |
| `SUPERMGMT_JOBS_RETRY_BASE` | `jobs.retry_base` | duration |
| `SUPERMGMT_HEALTH_ALLOWED_PRIVATE_CIDRS` | `health.allowed_private_cidrs` | list (comma-separated) |
| `SUPERMGMT_OUTBOUND_PROXY` | `outbound.proxy` | string |
| `SUPERMGMT_GITHUB_OIDC_AUDIENCE` | `github.oidc_audience` | string |
| `SUPERMGMT_GITHUB_CI_POLL_INITIAL` | `github.ci_poll_initial` | duration |
| `SUPERMGMT_GITHUB_CI_POLL_MAX` | `github.ci_poll_max` | duration |
| `SUPERMGMT_GITHUB_CI_TIMEOUT` | `github.ci_timeout` | duration |
| `SUPERMGMT_MCP_ENABLED` | `mcp.enabled` | bool |
| `SUPERMGMT_MCP_REMOTE_ENABLED` | `mcp.remote_enabled` | bool |
| `SUPERMGMT_MCP_OAUTH_ISSUER` | `mcp.oauth.issuer` | string |
| `SUPERMGMT_MCP_OAUTH_RESOURCE` | `mcp.oauth.resource` | string |
| `SUPERMGMT_MCP_OAUTH_JWKS_URL` | `mcp.oauth.jwks_url` | string |
| `SUPERMGMT_MCP_OAUTH_INTROSPECTION_URL` | `mcp.oauth.introspection_url` | string |
| `SUPERMGMT_MCP_OAUTH_REQUIRED_SCOPES` | `mcp.oauth.required_scopes` | list (comma-separated) |
| `SUPERMGMT_MCP_ALLOW_INTERACTIVE_EXEC` | `mcp.allow_interactive_exec` | bool |
| `SUPERMGMT_MCP_WRITE_TOOLS_ENABLED` | `mcp.write_tools_enabled` | bool |
| `SUPERMGMT_BACKUP_SCHEDULE` | `backup.schedule` | string |
| `SUPERMGMT_BACKUP_RETENTION` | `backup.retention` | int |
| `SUPERMGMT_BACKUP_DIRECTORY` | `backup.directory` | string |
<!-- END GENERATED ENV TABLE -->

## Server transport and TLS

Only for `instance.mode: server`. Validation (`internal/config/validate.go`):

```yaml
server:
  listen: 127.0.0.1:8787            # proxy: loopback or unix:/path or an absolute socket path
  public_url: https://mgmt.example.com
  tls:
    mode: proxy                     # proxy (default) | direct
    cert_file: ""                   # direct only; required then
    key_file: ""                    # direct only; required then
  trusted_proxies: ["127.0.0.1/32"] # proxy only; must be non-empty; IPs or CIDRs
  admin_socket: /run/supermgmt/admin.sock
```

- `proxy`: the daemon speaks plain HTTP and a reverse proxy terminates TLS. A non-loopback, non-Unix `listen` is a validation error. `X-Forwarded-For` and `X-Forwarded-Proto` are believed only from a peer inside `trusted_proxies`, and a forwarded proto other than `https` is a 400. A loopback connection is not trusted for anything else.
- `direct`: the daemon terminates TLS 1.2 or newer; `cert_file` and `key_file` are re-read on `SIGHUP` (a failed reload keeps the old pair). There is **no ACME and no certificate generation**.
- `admin_socket` is created with mode 0660 for the service user; only root or the service user may connect.
- Default `server.listen` (`127.0.0.1:8787`) is the proxy default. The installer picks `0.0.0.0:8443` for `--tls direct` and writes it explicitly.

See [installation.md](installation.md#tls-proxy-or-direct) and [cloudflare.md](cloudflare.md).

## OIDC

```yaml
auth:
  bootstrap:
    code_ttl: 24h
  oidc:
    enabled: true
    issuer: https://dex.example.com       # https, no userinfo; must equal the discovery document's issuer byte for byte
    client_id: supermgmt
    client_secret_ref: secret://auth/oidc-client-secret   # required when enabled; only secret:// is accepted
    allowed_domains: [example.com]        # optional; matched against a verified email
    allowed_endpoint_origins: []          # extra https origins, e.g. https://keys.example.com
```

- The **server** is the OIDC client and holds the client secret. The CLI logs in with Authorization Code + PKCE (S256) over a loopback redirect `http://127.0.0.1:<port>/callback`, or with the device authorization grant (`sm login --device`).
- Discovery trust: the document's `issuer` must equal `auth.oidc.issuer`; the authorization, token, device-authorization and JWKS endpoints must be `https` and on the issuer's origin or on an origin in `allowed_endpoint_origins` (an entry is a scheme and host with no path). The userinfo endpoint is never called; claims come only from the verified ID token (RS256, ES256 or EdDSA; `iss`, `aud`, `azp`, `exp`, `iat`, `nonce`, verified email).
- Discovery runs on first use rather than at start, so a wrong issuer or an unreachable IdP fails at login time with `PROVIDER_ERROR`.
- Requests to the IdP go through the outbound filter: private ranges are allowed, loopback and cloud-metadata addresses never, redirects are not followed, bodies are capped. An IdP that listens only on loopback cannot be used.
- The token endpoint authenticates the client with HTTP Basic (`client_secret_basic`).

**The only identity provider exercised is Dex**, `ghcr.io/dexidp/dex:v2.45.1`, by hand in a spike (code flow with PKCE and the device grant, confidential client); the automated Dex end-to-end suite was not part of the code this page was written against. No other IdP has been tested; Google, Okta, Entra ID, Keycloak and the rest are untested assumptions. Real-IdP login is on the [manual checklist](manual-checks/m2-handoff.md).

Dex specifics found while testing:

- A Dex confidential client rejects a loopback redirect with a port it has not registered. Register one fixed redirect (`http://127.0.0.1:5555/callback`, say) and sign in with `sm login --callback-port 5555`.
- With the device grant, Dex puts the `client_secret` into the verification URL shown in the browser. See [security.md](security.md#oidc-and-the-device-flow-client-secret) before enabling the device flow with Dex.
- Register Dex's `/device/callback` for the device flow; use an issuer at the root of the host (an issuer path puts that callback outside it).

## Backup

```yaml
backup:
  schedule: "0 3 * * *"   # 5-field cron, UTC; default in server mode; empty in local mode
  retention: 14           # newest archives to keep, at least 1
  directory: ""           # default <instance.data_dir>/backups
```

In local mode the schedule only runs when `daemon.resident: true`. Details, restore and key handling: [operations.md](operations.md).

## Environments and providers

These are lists of structures and are set in the file only (see SPEC §8.2.1 and §8.3).

```yaml
environments:
  - name: production
    risk_level: production        # development | staging | production
    approvals_required: 1         # minimum quorum for operational and higher writes, 1..5

providers:
  - type: ssh
    name: ovh-prod-01
    endpoint:
      host: 10.42.0.10
      port: 22
      user: supermgmt             # default; the account node.setup creates
      admin_user: alex            # required; your own account on the node
      host_public_key: "ssh-ed25519 AAAA..."
    credential_ref: secret://ssh/default      # default; the instance SSH identity
    admin_credential_ref: ssh-agent://default # default in local mode; none in server mode
    environment: production
```

An environment with `risk_level: production` makes operational writes (service restarts, `node.setup`) require approval by default. At daemon start the file's environments and SSH providers are written to the database as the `system` actor; a change bumps `spec_revision` and is audited, and a provider removed from the file retires its node. Nodes added through `sm nodes add` are never touched by the file. `user` is the account `node.setup` creates; until setup, the node is read as `admin_user`. See [providers.md](providers.md). Provider tokens always use `secret://` references. A Proxmox provider (`type: proxmox`, M3) is applied the same way and then synced; its keys, `verify_tls: true` (required) and `ca_file` are described in [providers.md](providers.md#proxmox).

## GitHub

A GitHub provider and the `github:` block configure the GitHub connector used by apps and deployments ([deployments.md](deployments.md)). Applications and their targets are **not** in this file; they are created with `sm apps` or the API.

```yaml
providers:
  - type: github
    name: github
    api_url: https://api.github.com            # default; the exact origin is the only host contacted
    credential_ref: secret://providers/github/token     # must be secret://providers/<name>/token
    webhook_secret_ref: secret://providers/github/webhook   # server mode only; must sit under secret://providers/<name>/
    ca_file: ""                                 # optional absolute path (GitHub Enterprise Server)

github:
  oidc_audience: ""     # default: server.public_url; required `aud` of GitHub Actions tokens
  ci_poll_initial: 15s
  ci_poll_max: 2m       # server mode: also the backstop poll next to webhooks
  ci_timeout: 2h

environments:
  - name: production
    risk_level: production
    require_provenance: true         # only an attestation binds the deployed digest
    allow_automatic_rollback: false  # default false
```

- `api_url` must be https without userinfo, query, fragment or trailing slash; `credential_ref` and `webhook_secret_ref` must be `secret://`; `ca_file` must be absolute (`internal/config/github.go`, tests `TestGitHubProviderRejections`, `TestGitHubProviderAcceptsEnterpriseServer`). The credential is a read-only fine-grained token; whether the permission set listed in [deployments.md](deployments.md#register-github) is exactly sufficient is **not verified against real GitHub**.
- Redirects from the GitHub API are followed only up to three hops and only to the exact origin (scheme, host and port) of `api_url`; the token is attached only to requests to that origin (`TestRedirect_OriginPinned`, `TestClient_TokenNeverOffOrigin`). Real GitHub's redirect behavior is **not verified**.
- Setting `github.oidc_audience` (or `server.public_url`, its default) enables Actions OIDC bearers on the HTTPS listener. With neither set, Actions tokens are not accepted (`TestGitHubActionsTokensAreAcceptedOnlyWithAnAudience`).
- The webhook is `POST /api/v1/github/webhook`, HTTPS listener only, authenticated by HMAC-SHA256 over the body with the secret behind `webhook_secret_ref`. Local mode has no webhook and only polls.
- `require_provenance` and `allow_automatic_rollback` are read from the file at start like the other environment keys. A `GitHub` provider can also be registered by `POST /api/v1/providers` with `type: github`; the request is gated by `provider.write` and may park for approval (`TestPostProvidersAcceptsAGitHubProvider`).
- `github.ci_poll_*` and `ci_timeout` are read by the CI watcher (`internal/daemon/assemble.go`); the generated table above lists their environment variables.

## Policy

Permissions are granted only by policy rules. The binary embeds a built-in default policy; `security.policy_file` replaces it entirely. See [`examples/policies.yaml`](../examples/policies.yaml) and [security.md](security.md). The policy package can diff a user policy against the built-in default.

## Defaults that depend on mode

- `security.allow_self_approval` defaults to `true` in local mode and `false` in server mode (SPEC §11.4); set it explicitly to override.
- Local mode keeps the daemon alive while a client is connected or a job is not finished (including `awaiting_approval`), then exits after `daemon.idle_exit` unless `daemon.resident: true`. `sm install local --resident` registers a user unit (systemd) or launch agent (macOS) that starts a resident daemon at login; the unit and agent are rendered and tested with fakes, and a real launchd or user-systemd run is not verified.
- `backup.schedule` defaults to `0 3 * * *` (UTC) in server mode and is empty in local mode; a schedule in local mode runs only when the daemon is resident.
