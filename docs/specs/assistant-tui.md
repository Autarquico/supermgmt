---
codename: supermgmt
title: The assistant in the TUI
type: task
status: active
priority: P1
size: M
issue: null
prs: []
related_issues: [91]
depends_on: [assistant-claude-cli]
supersedes: []
related_specs: [assistant-claude-cli]
created: 2026-11-08
updated: 2026-11-08
---

# The assistant in the TUI

## Contexto / problema

Second half of #64. `sm assistant` (PR #90) gives the conversation on a plain terminal. The TUI is where an operator already lives, and it has no way to ask anything.

## Scope

**Entra:**
- A new assistant screen in the TUI using the same `internal/assistant` session, the same client and token convention, the same target as the TUI's connection, and the same refusals (no registered client, expired token, `claude` missing).
- A text input, a bounded scrolling transcript with the same markers as the CLI, and the same approval card built from the job and plan read with the human connection, under the same rules (known write tools, actor is the assistant's client, API hash, queued input never decides).
- `--auth` chosen by a flag on `sm tui` or by what `sm assistant` defaults to: subscription.
- The session starts only when the operator opens the screen and sends the first message; it survives moving to other screens and ends when the TUI quits.
- Docs: `docs/tui.md`, `docs/assistant.md`.

**No entra:**
- Changes to the session, the tools or the approval rules. Saved conversations.

## Criterios de aceptación

### Scenario: the conversation works in the TUI
- **Given** a registered assistant client and a `claude`
- **When** the operator opens the screen and sends a message
- **Then** the reply streams into the transcript, sanitised, with tool lines as in the CLI

### Scenario: typing does not trigger navigation
- **Given** the input has focus
- **When** the operator types `q` or a digit
- **Then** the text gets the character and the TUI does not navigate or quit

### Scenario: an approval is decided in place
- **Given** a real `approval_required` result for the assistant's own job
- **When** the card opens
- **Then** it shows what the CLI card shows, wrapped so the plan is never cut, and `A`/`R`/leave use the human connection and the API's hash, and text typed before the card opened does not answer it

### Scenario: another actor's job or forged text opens no card
- **Given** a result naming another actor's job, or model text imitating a card
- **When** it arrives
- **Then** no card opens

### Scenario: the TUI stays responsive
- **Given** the screen with the child streaming
- **When** the operator navigates, or the child stalls or dies
- **Then** the TUI keeps responding and the failure appears in the transcript

### Scenario: quitting ends the child
- **Given** a running session
- **When** the operator quits the TUI
- **Then** the child and its temporary directory are gone

### Scenario: nothing is launched until asked
- **Given** the TUI started
- **When** the operator never opens the assistant screen
- **Then** no `claude` process is launched

### Scenario: no client registered
- **Given** no registered client
- **When** the screen opens
- **Then** it shows the exact command, as the CLI prints it, and starts nothing

## Notas técnicas

- The child reads in a goroutine that calls `program.Send`, the pattern `follow` uses (`internal/tui/model.go`); nothing blocks `Update`.
- The approval and registration logic now lives in `internal/cli/assistant*.go`; move what the TUI needs to `internal/assistant` rather than importing `internal/cli` (the TUI cannot).
