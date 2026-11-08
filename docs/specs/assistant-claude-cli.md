---
codename: supermgmt
title: "sm assistant: ask in natural language, through SuperMgmt's MCP tools"
type: task
status: draft
priority: P1
size: L
issue: null
prs: []
related_issues: []
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
- The model has only SuperMgmt's MCP tools. The child runs with no built-in tools (`--tools ""`), only one MCP server (`--strict-mcp-config --mcp-config`, launching `sm mcp` with a registered client token), those tools pre-approved, and anything else denied instead of prompting. A test pins the argument vector.
- The child gets a sanitised environment: no `SUPERMGMT_*`, no SSH agent socket, no SuperMgmt credentials; the API key only in `--auth api-key`.
- The assistant uses its own registered MCP client (`sm mcp clients add`), never the human's credential. If none exists, `sm assistant` explains the one command to run; it does not register by itself.
- Approvals in place: when a tool result says `approval_required`, `sm` fetches the job and plan with the human's own connection and shows them (never text written by the model); the human approves or rejects with the plan hash from the API, or leaves it. The approval uses the human's credential and rules. The model is told the outcome in the next turn.
- The TUI gets an assistant screen with the same transcript and approval card, with the child in the background; model output goes through `textsafe` before rendering.
- `claude` missing or not signed in: a clear message, nothing is installed.
- Docs: `docs/assistant.md`, the terms note, `docs/mcp.md`, `docs/tui.md`, CLI reference.

**No entra:**
- Other model CLIs (an adapter can come when a second one is real). Saving conversations. Any new tool: the assistant has what MCP has.

## Criterios de aceptación

### Scenario: the model can only use SuperMgmt's tools
- **Given** `sm assistant` in either mode
- **When** the child is launched
- **Then** its arguments give it no built-in tools, one MCP server and pre-approval only for that server's tools, and in api-key mode `--bare`

### Scenario: the child inherits nothing from SuperMgmt
- **Given** an environment with `SUPERMGMT_*`, an SSH agent socket and a stored human token
- **When** the child is launched
- **Then** none of them reach it, and only the assistant's MCP token is used, by `sm mcp`

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
- **Then** its content comes from the job and plan read with the human's connection; approving sends the API's plan hash with the human's credential, and the model's token could not have approved

### Scenario: a hostile model cannot fake a card
- **Given** model text or tool output with control sequences or a fake approval prompt
- **When** it is rendered
- **Then** it is sanitised and shown as model text; only a real `approval_required` result opens a card

### Scenario: no assistant client registered
- **Given** no registered client for the assistant
- **When** `sm assistant` starts
- **Then** it prints the command to register one and exits without launching the model

### Scenario: the TUI stays responsive
- **Given** the assistant screen with the child streaming
- **When** the operator navigates or the child stalls or dies
- **Then** the TUI keeps responding and the failure is shown in the transcript

## Notas técnicas

- `-p --input-format stream-json --output-format stream-json --verbose`; the stream's message schema is not documented for the CLI, so a recorded real run fixes the parser's fixtures.
- Without `--bare`, `claude` loads the operator's hooks and CLAUDE.md. Use `--setting-sources` to narrow it as far as the CLI allows, and say what remains in the guide: they are the operator's own configuration, and the model still has no tools but SuperMgmt's.
- The child runs from an empty temporary directory, so no project configuration applies.
- The process lives in a `tea.Cmd` stream, never in `Update` (`internal/tui/api.go:14-15`).
