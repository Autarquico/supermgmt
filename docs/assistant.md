# Ask in natural language

> **Status: experimental.** The session was tested against the real `claude` CLI on macOS with a stub MCP server; the rest of the path uses a fake `claude`. Linux sign-in is not verified.

`sm assistant` opens a conversation in your terminal. You ask in natural language ("why is web failing on vps1?"), and a Claude model works with SuperMgmt's own [MCP tools](mcp.md). It has the same tools, policy, audit and approval floor as any MCP client.

## Before you start

You need the official [`claude` CLI](https://code.claude.com/docs/en/setup) on your `PATH`, signed in. SuperMgmt does not install it.

The assistant is an MCP client of its own, so register it once. Run `sm assistant` first: when the client is missing, it prints the exact command to run for your current target and stops. On the local daemon that is:

```bash
sm mcp clients add assistant --keychain supermgmt-assistant
```

A remote profile, or another `--client`, has its own keychain entry and needs `--https` ([what that needs](mcp.md#drive-a-server-from-your-workstation)), so copy the line `sm assistant` prints. Registration may need approval: approve it (`sm approvals`, then `sm jobs approve <job-id> --plan-hash <hash>`), then run the same command again. If your machine has no keychain, `sm assistant` tells you which token file to use.

Reads work by default. For the model to act, set `mcp.write_tools_enabled: true` ([Writes are off by default](mcp.md#writes-are-off-by-default)).

## Which account it uses

| Mode | How | Cost |
|---|---|---|
| `--auth subscription` (default) | Runs your own `claude`, signed in with your own account | Your Claude plan |
| `--auth api-key` | Runs `claude --bare` with `ANTHROPIC_API_KEY` from your environment | Billed per use on your API account |

SuperMgmt never reads, stores or asks for your Claude credentials, and it offers no Claude sign-in. If `claude` is not signed in, run `claude` in a terminal and sign in there.

What you type and what the tools return, including service logs, go to Anthropic through your `claude`, under the terms of that account. SuperMgmt keeps no transcript.

**Offering `sm` to other people?** As of 2026-11-08, [Anthropic's terms](https://code.claude.com/docs/en/legal-and-compliance) allow running Claude Code in your product if you accept the Commercial Terms, the `claude` binary is unmodified with none of its sign-in methods removed or restricted, and each person authenticates with their own subscription or their own API key, billed to them. You may not pay for, resell or intermediate their usage. `--auth subscription` fits that when each person signs in to their own `claude`, as `sm` never touches those credentials. `--auth api-key` is for a key you or they provision. Advertised limits of Pro, Max and Ultra plans assume ordinary, individual usage. Read the page yourself before you distribute `sm`: this is a summary, not legal advice.

## A conversation

```text
$ sm assistant
[sm] assistant on profile lab (client assistant, your claude subscription). /exit or Ctrl-D to end.
> which services failed on vps1 today?
```

End with `/exit` or Ctrl-D. A blank line does nothing.

When the assistant's token has expired, `sm assistant` stops before starting and prints the steps to replace it.

If `sm` cannot start its tools for the session, the usual cause is, on a server, `mcp.token_over_https` not being set ([how to set it](mcp.md#drive-a-server-from-your-workstation)).

## In the TUI

Press `8` for the assistant screen, or start the TUI with `sm tui --auth api-key` for the API key mode. Nothing runs until you send the first message. The conversation continues while you visit other screens and ends when you quit.

A card opens when an approval is needed. Scroll with `pgup` and `pgdn`, wait for it to arm (it arms once it has been on your screen for a moment with no key pressed), then press `A`, wait for the confirmation to arm the same way, and press `y`, or `R` and give a reason. At the confirmation, only `y` after the pause approves; any other key, or a key during the pause, goes back. `Esc` leaves that job pending and shows the next card, if any. Pasted text is taken as one line.

On this screen `q`, digits and `?` are text. `Esc` leaves the screen, `pgup` and `pgdn` scroll the transcript, `ctrl+x` stops a session that is working, and `ctrl+c` quits the TUI and ends the session.

## What the model can do

The model has only SuperMgmt's tools. `claude` runs with no built-in tools (no shell, no files, no web fetch tool), one MCP server, no slash commands, and no saved session, from an empty temporary directory. After your first message, `claude` reports its session and `sm` checks its tools and its server; if any tool is not SuperMgmt's, it stops before showing any output or letting any tool run.

The limits of that:

- It relies on `claude` honouring those options. With no tools the model cannot read files or the environment, but any process running as you can reach what you can, including the local daemon's socket and your keychain.
- In subscription mode, policies your administrator manages for `claude` still apply.
- Server-side features of your Anthropic account are not controlled by these options.

## Approvals

The model can never approve. When it requests something that needs approval, `sm` shows a card built from the job and plan it reads with **your** connection, not from anything the model wrote. It shows a job only if that job is waiting for approval and the assistant asked for it.

Answer `approve`, `reject` or `leave`. There is no default. Approving uses your own credential and permissions, so you need the right to approve that action. The model is then told what you decided. If standard input is not a terminal, `sm` names the job and does not approve it; use `sm approvals`. Text typed while the model was working never answers a card. An approval that still needs more approvers is recorded, and `sm` says so.

## Everything the model says is untrusted

Model output is cleaned of control sequences before it reaches your terminal. Tool calls, failures and the status of writes appear, cleaned and shortened, after the `|` marker; other tool results are not displayed. Text that looks like an approval prompt is only text: real approvals come from the card described above.
