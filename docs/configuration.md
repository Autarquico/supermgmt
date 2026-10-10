# Configuration

SuperMgmt reads one YAML file. The schema is defined in SPEC §8 (`docs/spec/SUPERMGMT-SPEC.md`) and implemented in `internal/config`. A complete example is [`examples/config.yaml`](../examples/config.yaml); a policy example is [`examples/policies.yaml`](../examples/policies.yaml).

> **Status:** pre-alpha. The loader and validator back `sm config validate` and `sm doctor --offline`, and since M1 the local daemon reads the file at start. Accepting a key does not mean its feature is implemented: [Which keys M1 reads](#which-keys-m1-reads) lists what is wired. Server mode and auth: M2, Proxmox: M3, GitHub and deployments: M4, MCP: M5.

## File location

Pass `--config <path>`. The default locations (SPEC §8.1) are:

| Mode | Config file | Database |
|---|---|---|
| Linux server | `/etc/supermgmt/config.yaml` | `/var/lib/supermgmt/supermgmt.db` |
| Linux, local user | `$XDG_CONFIG_HOME/supermgmt/config.yaml` (default `~/.config/supermgmt/`) | `$XDG_DATA_HOME/supermgmt/supermgmt.db` (default `~/.local/share/supermgmt/`) |
| macOS, local user | `~/Library/Application Support/SuperMgmt/config.yaml`, unless `XDG_*` variables are set | `~/Library/Application Support/SuperMgmt/supermgmt.db` |

Paths that you do not set (`instance.data_dir`, `storage.sqlite.path`, `security.keys_dir`, `ssh.known_hosts_file`, `backup.directory`) are derived from the mode: the server locations above for `instance.mode: server`, the local-user locations otherwise. `security.keys_dir` defaults to `<instance.data_dir>/secrets/keys` and holds the KEK files; back them up separately from the database ([security.md](security.md#secrets-and-the-instance-ssh-identity-m1)).

The daemon socket is `$XDG_RUNTIME_DIR/supermgmt/sm.sock` on Linux when that variable is set, otherwise `<state dir>/run/sm.sock` (state dir `$XDG_STATE_HOME/supermgmt`, default `~/.local/state/supermgmt`; on macOS `~/Library/Application Support/SuperMgmt/state`). `daemon.socket` overrides it. The autostarted daemon writes its log to `daemon.log` in the state directory.

## Which keys M1 reads

Read by the local daemon and CLI:

- `instance.*`, `daemon.*` (`socket`, `idle_exit`, `resident`), `storage.sqlite.*`
- `security.keys_dir`, `security.policy_file`, `security.approval_ttl`, `security.allow_self_approval`
- `ssh.*` timeouts and pool limits: `connect_timeout`, `command_timeout`, `keepalive_interval`, `max_dials_in_flight`, `max_connections`, `max_sessions_per_connection`, `idle_connection_ttl`
- `refresh.*`, `jobs.*`, `server.shutdown_timeout`
- `environments` and SSH `providers`, applied when the daemon starts

Validated but not read in M1 (no reader outside the config package):

- `ssh.known_hosts_file`: the pinned host key in the database is the only trust anchor ([ADR-0015](adr/0015-ssh-transport-and-command-templates.md)).
- `ssh.host_key_policy` (must be `strict`) and `ssh.logs_mode`: the log mode of a node comes from the `logs_mode` parameter of its `node.setup` plan.
- `ui.theme`, `security.session_ttl`, `security.redact_command_output`
- the rest of `server.*`, `auth.*`, `health.*`, `outbound.*`, `github.*`, `mcp.*`, `backup.*`
- Proxmox providers (M3)

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
| `secret://<path>` | encrypted secret in the SuperMgmt store. In M1 only `secret://ssh/default` (the instance SSH identity) resolves; any other name fails with `CAPABILITY_UNAVAILABLE`. The secrets CLI arrives in M2 |
| `ssh-agent://default` | the daemon user's `$SSH_AUTH_SOCK`; local mode only, rejected in server mode. In M1 it serves `admin_user` only |
| `file://<abs-path>` | key file at an absolute path; discouraged, supported for migration |

## Environment overrides

Every scalar setting and every string list can be overridden with an environment variable named `SUPERMGMT_` plus the upper-cased YAML path with dots replaced by underscores (`server.listen` becomes `SUPERMGMT_SERVER_LISTEN`). Lists are comma-separated. Durations use Go syntax (`30s`, `10m`). Lists of structures, `environments` and `providers`, can only be set in the file.

Variables that start with `SUPERMGMT_` but are neither overrides nor installer variables are reported as warnings and ignored. The installer's own variables (such as `SUPERMGMT_VERSION` and `SUPERMGMT_CHANNEL`, planned M2) are not configuration overrides.

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

An environment with `risk_level: production` makes operational writes (service restarts, `node.setup`) require approval by default. At daemon start the file's environments and SSH providers are written to the database as the `system` actor; a change bumps `spec_revision` and is audited, and a provider removed from the file retires its node. Nodes added through `sm nodes add` are never touched by the file. `user` is the account `node.setup` creates; until setup, the node is read as `admin_user`. See [providers.md](providers.md). Provider tokens always use `secret://` references. Proxmox providers are validated but ignored until M3.

## Policy

Permissions are granted only by policy rules. The binary embeds a built-in default policy; `security.policy_file` replaces it entirely. See [`examples/policies.yaml`](../examples/policies.yaml) and [security.md](security.md). The policy package can diff a user policy against the built-in default.

## Defaults that depend on mode

- `security.allow_self_approval` defaults to `true` in local mode and `false` in server mode (SPEC §11.4); set it explicitly to override.
- Local mode keeps the daemon alive while a client is connected or a job is not finished (including `awaiting_approval`), then exits after `daemon.idle_exit` unless `daemon.resident: true`. A user unit that starts a resident daemon at login arrives in M2.
- `backup.schedule` defaults to nightly in server mode and is disabled in local mode unless the daemon is resident (backups: M2).
