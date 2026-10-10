# Configuration

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
