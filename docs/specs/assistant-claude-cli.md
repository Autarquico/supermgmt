---
codename: supermgmt
title: "sm assistant: ask in natural language, through SuperMgmt's MCP tools"
type: task
status: active
priority: P1
size: L
issue: null
prs: []
related_issues: [89]
depends_on: [mcp-tool-coverage, mcp-https-token, mcp-node-tools]
supersedes: []
related_specs: []
created: 2026-11-08
updated: 2026-11-08
---

# sm assistant: ask in natural language, through SuperMgmt's MCP tools

## Contexto / problema

Issue #64. After #63, MCP drives what `sm` operates, but the operator still needs an external host to talk to it. `sm` should offer a conversational space where the operator asks in natural language and a model works with SuperMgmt's own tools, under the same policy, audit and approval floor as any MCP client.

Decisions (user, 2026-11-08): the model runs through the official `claude` CLI, with the operator's own subscription by default and an API key as an explicit mode.

Anthropic's terms do not allow a developer to route requests through a user's subscription on that user's behalf from a product, and do allow a person to use the official binary with their own subscription. They do not settle a program launching the operator's own `claude`. So: SuperMgmt never reads, stores, proxies or asks for Claude credentials or offers a Claude login; the operator's own `claude` handles its own sign-in; the guide states this and says that anyone offering `sm` to other people must use the API key mode.

## Scope

**Entra:**
- `sm assistant`: a conversation on the terminal. `--auth subscription` (default) runs the operator's `claude`; `--auth api-key` runs it with `--bare` and `ANTHROPIC_API_KEY` from the environment.
- The model has only SuperMgmt's MCP tools. The child runs with no built-in tools (`--tools ""`), only one MCP server (`--strict-mcp-config --mcp-config`, launching `sm mcp` with a registered client token), those tools pre-approved, anything else denied instead of prompting (`--permission-prompts none`), no slash commands, no saved session and SuperMgmt's own system prompt. A test pins the argument vector and refuses `--dangerously-skip-permissions`. When the session reports itself (`claude` does so after the first message), its tools must all be SuperMgmt's and its server connected; otherwise `sm` stops the child before any output is shown or any tool runs.
- The child gets an allowlisted environment (home, path, locale, proxy, `CLAUDE_CONFIG_DIR`); the API key only in `--auth api-key`. No `SUPERMGMT_*`, no SSH agent socket. `sm mcp` gets its target explicitly (`--profile` or `--config`), so it reaches the same instance as `sm assistant`. The guide says what this protects: with no tools the model cannot read the environment, and any process of the operator's user can reach what the operator can.
- The assistant uses its own registered MCP client (default name `assistant`, token in the keychain entry `supermgmt-assistant` or a 0600 file in the configuration directory), never the human's credential. If none exists, or a remote target needs `--https`, `sm assistant` prints the exact command to run; it does not register by itself.
- Approvals in place: only a result of a known write tool, parsed strictly as a whole, with `status: approval_required` opens a card. `sm` then fetches the job with the human's own connection and shows it only if it is awaiting approval and its actor is the assistant's client. The card comes from the job and plan (never from model text); the human approves or rejects with the plan hash from the API, or leaves it. The model is told the outcome in the next turn.
- All model output goes through `textsafe` before reaching a terminal.
- A second PR adds the TUI screen with the same session, transcript and approval card.
- `claude` missing or not signed in: a clear message, nothing is installed.
- Docs: `docs/assistant.md`, the terms note, `docs/mcp.md`, `docs/tui.md`, CLI reference.

**No entra:**
- The TUI screen in the first PR. Other model CLIs (an adapter can come when a second one is real). Saving conversations. Any new tool: the assistant has what MCP has.

## Criterios de aceptación

### Scenario: the model can only use SuperMgmt's tools
- **Given** `sm assistant` in either mode
- **When** the child is launched
- **Then** its arguments give it no built-in tools, one MCP server and pre-approval only for that server's tools, and in api-key mode `--bare`

### Scenario: a session with other tools does not start
- **Given** a `claude` whose session reports any tool outside SuperMgmt's, or its server not connected
- **When** the session starts
- **Then** `sm` stops it before showing any output or letting any tool run, and says why

### Scenario: the child inherits nothing from SuperMgmt
- **Given** an environment with `SUPERMGMT_*`, an SSH agent socket and a stored human token
- **When** the child is launched
- **Then** only the allowlisted variables reach it, and `sm mcp` uses the assistant's token against the same target as `sm assistant`

### Scenario: subscription mode never touches Claude credentials
- **Given** `--auth subscription`
- **When** the assistant runs
- **Then** `sm` reads no Claude credential and passes no API key, and a `claude` that is not signed in produces a message telling the operator to sign in with `claude`

### Scenario: api-key mode needs the key
- **Given** `--auth api-key` and no `ANTHROPIC_API_KEY`
- **When** the assistant starts
- **Then** it refuses, and the key never appears in arguments or output

### Scenario: an approval is decided by the person, from the API
- **Given** a tool result `approval_required` for a job, with model text claiming something else
- **When** the card is shown
- **Then** its content comes from the job and plan read with the human's connection, and a job whose actor is not the assistant's client opens no card; approving sends the API's plan hash with the human's credential, and the model's token could not have approved

### Scenario: a hostile model cannot fake a card
- **Given** model text or tool output with control sequences or a fake approval prompt
- **When** it is rendered
- **Then** it is sanitised and shown as model text; only a real `approval_required` result opens a card

### Scenario: no assistant client registered
- **Given** no registered client for the assistant
- **When** `sm assistant` starts
- **Then** it prints the command to register one and exits without launching the model

## Notas técnicas

- `-p --input-format stream-json --output-format stream-json --verbose`; the stream's message schema is not documented for the CLI, so a recorded real run fixes the parser's fixtures.
- Without `--bare`, `claude` loads the operator's hooks and CLAUDE.md. Use `--setting-sources` to narrow it as far as the CLI allows, and say what remains in the guide: they are the operator's own configuration, and the model still has no tools but SuperMgmt's.
- The child runs from an empty temporary directory, so no project configuration applies.
- A real run (`claude` 2.1.311) showed `--safe-mode` drops `--mcp-config`, so subscription mode uses `--setting-sources ""`. Fixtures in `test/fixtures/claude-stream/`.
