# claude stream-json fixtures

Output of `claude -p --output-format stream-json --verbose`, per claude version (directory name).

2.1.311, recorded 2026-11-08 on macOS with the operator's own signed-in `claude` (model haiku) and a stub
stdio MCP server exposing one read tool `infra_ping`. Redacted: ids, session ids, uuids, paths, plugin
list, socket path, timestamps.

- `tool-call.jsonl` recorded: init (tool `mcp__sm__infra_ping`, server `sm` connected), assistant `tool_use`,
  user `tool_result`, assistant text, result. Run with the argv of `internal/assistant` (`--setting-sources ""`).
- `not-signed-in-no-mcp.jsonl` recorded with an environment lacking USER/LOGNAME and `--safe-mode`: init
  with no tools and no MCP server (`--safe-mode` drops `--mcp-config`), then `Not logged in` as an error result.
- `approval-required.jsonl` HAND-WRITTEN from `tool-call.jsonl`: the tool is `infra_restart_service` and its
  result the `WriteResult` JSON of `internal/mcp` with `status: approval_required`.

Findings that fixed the design: `--safe-mode` ignores `--mcp-config`, so `--setting-sources ""` is used;
the init message arrives only after the first user message, not at start; a stripped environment needs
`USER` or `LOGNAME` for the macOS keychain login.
