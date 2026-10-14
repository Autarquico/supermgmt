# Using the TUI

The terminal UI is the everyday way to look at your nodes, services, jobs and deployments, and to act on them. It is a client of the same daemon API as the `sm` commands, so anything you do here goes through the same plans, policy and approvals.

## Open it

Run `sm` in an interactive terminal, or `sm tui`. Outside a terminal (a pipe, a script, CI), plain `sm` prints its help instead, and `sm tui` exits with a usage error.

The TUI talks to whatever your active profile points at: the local daemon by default, or a remote server after `sm profile use <name>`. With the local daemon it starts the daemon if needed and waits up to 10 seconds for it, so a daemon that cannot start is a plain error instead of an empty screen.

- **Terminal size:** at least 40 columns by 10 rows. Smaller, it says so instead of drawing a broken frame. From 72 columns, Resources and Approvals show a list and a detail pane side by side.
- **Updates:** the current screen reloads every 5 seconds. Against a remote server it also follows the server's live event stream, so changes show up at once. Press `r` to reload now. The Settings screen tells you which mode you are in.

## The frame

Every screen has the same four parts:

- **Header:** the screen name, and the counts of nodes, Proxmox guests, nodes online, warnings and approvals waiting.
- **Body:** the screen itself.
- **Status line:** what just happened (`job … is waiting for approval`, an error with its correlation ID), or the state of the data: `loading…`, `error · …` before the first load, `stale · …` when a reload failed and you are looking at the last good data.
- **Key line:** the keys that work on this screen.

Meaning never depends on color alone. A glyph or a word carries it too:

| Glyph or word | Meaning |
|---|---|
| `●` | reachable node, running guest; for a service, its health column says healthy or unhealthy |
| `○` | unreachable node, stopped guest |
| `◌` | unknown, or a Proxmox object SuperMgmt cannot confirm |
| `▸` | the selected row |
| `[stale]` | the node's data is out of date |
| `[template]`, `[absent]`, `[inaccessible]` | a Proxmox template, a guest gone from Proxmox, a guest the API token cannot see |

## Keys everywhere

| Key | Does |
|---|---|
| `1` to `7` | Dashboard, Resources, Jobs, Approvals, Events, Providers, Settings |
| `8`, `9` | Applications, Deployments |
| `j` `k` or the arrow keys | move the selection |
| `g` `G` (or Home, End) | first row, last row |
| `enter` | open the selected item |
| `esc` | back to the previous screen |
| `r` | reload the screen now |
| `/` | open the command palette |
| `?` | open or close Help |
| `q`, `ctrl+c` | quit |

Letters are case-sensitive: `r` reloads, `R` restarts a service or rejects a plan. While the palette or a prompt is open, keys type text; `esc` closes it.

## Screens

| Screen | Open with | What it shows | Keys on this screen |
|---|---|---|---|
| Dashboard | `1` | Node counts, nodes that need attention (unreachable or stale), plans awaiting approval, active jobs | |
| Resources | `2` | Nodes grouped by provider; Proxmox guests nested under their cluster node. With room, a detail pane for the selected node | `enter` node, `v` services, `s` SSH, `d` lazydocker |
| Node | `enter` on Resources | Environment, provider, metrics, capabilities, setup state, endpoint, connection, addresses, tags, and the first services | `v` services, `s` SSH, `d` lazydocker, `p` probe |
| Services | `v` | The node's services: name, runtime, status, health | `enter` service, `l` logs |
| Service | `enter` on Services | Runtime, native ID, status, health, available actions, metadata | `l` logs, `R` restart, `S` start, `X` stop |
| Logs | `l` | The last log lines of the service, marked `truncated` when cut | `j` `k` scroll, `g` top, `G` end |
| Jobs | `3` | The last 100 jobs: ID, type, state, risk, created. Failed jobs and jobs awaiting approval stand out | `enter` job, `c` cancel |
| Job | `enter` on Jobs | State, risk, attempts, plan hash, error, and each step with its pre-state and evidence | `c` cancel |
| Approvals | `4` | Plans waiting for a decision, and the selected plan in full | `A` approve, `R` reject |
| Events | `5` | The last 100 audit events, newest first: time, severity, action, result, correlation ID | |
| Providers | `6` | Providers with type, origin, status, last sync and last error. Read-only | |
| Settings | `7` | Mode, profile, server, how the screen updates, and who you are: name, ID, type, credential, roles. Read-only | |
| Applications | `8` | Apps with their repository and target environments | |
| Deployments | `9` | Deployments, newest first: kind, app and environment, state, commit | `enter` timeline |
| Deployment | `enter` on Deployments | State, commit, plan, known-good flag, images, each step with its result, and the deployment's events | |
| Help | `?` | Every key and the palette syntax | |

The `s`, `d` and `p` keys need an SSH endpoint. A Proxmox VM or container has none, so on a guest they are refused with a hint to use `power` from the palette.

## Acting: plans first, then confirmation

Nothing that changes a node runs from a single key press. When you press `R`, `S` or `X` on a service, or use `setup` or `power` in the palette, the TUI asks the daemon to build a plan and shows it:

- the action and its numbered steps;
- the impact (how many targets) and the risk;
- the plan hash, which is what an approval binds to;
- what happens next: `Runs as soon as it is submitted.`, `Needs N approval(s) before it runs.`, or `cannot submit: policy: deny (…)` when policy refuses it.

Press `y` or `enter` to submit, `n`, `esc` or `q` to cancel. A plan that policy denies cannot be submitted.

Some details worth knowing:

- `R`, `S` and `X` appear only for actions the service offers. A node that has not been set up offers none; set it up with `/ setup <node>`.
- `/ setup <node> docker` shows a warning first: Docker access adds the `supermgmt` user to the `docker` group, which is equivalent to root on that node.
- One action runs at a time. If an action times out, the status line says it may still have been applied: check Jobs before you try again.
- `c` on a job asks for confirmation before it cancels; a job that already finished is left alone.

## Approving and rejecting

Open Approvals with `4`. The left pane lists what is waiting (job, type, approvals so far out of the quorum); the right pane shows the selected plan: steps, impact, risk, environments, approvals and when they expire.

- `A` approves **the plan hash shown on screen**. If the plan changes before it runs, the job fails as stale instead of running something you did not read.
- `R` asks for a reason, then rejects. A rejection is final.
- If a plan cannot be read, the pane says `the plan could not be read: do not approve it`.

Whether you may approve your own plans, and how many approvals a plan needs, is set by policy and configuration: see [Policies and approvals](policies.md).

## Command palette

Press `/`, type a command, press `enter`. `esc` closes the palette without running anything. The key line under the prompt lists the commands; Help (`?`) shows their full syntax.

| Command | Does |
|---|---|
| `ssh <node> [tool]` | Opens a session on the node. `tool` is `shell` (the default), `lazydocker`, `btop` or `tmux` |
| `logs <service>` | Opens the service's logs. The service must already be loaded: open its node's services first |
| `services <node>` | Opens the node's services |
| `setup <node> [docker] [broker]` | Plans the node setup. `docker` grants Docker access; `broker` uses the log broker instead of the default journal access |
| `probe <node>` | Probes the node now |
| `power <node> <start\|shutdown\|reboot\|stop>` | Plans a power action on a Proxmox VM or container. `stop` cuts power without a clean shutdown and is high risk |
| `refresh` | Reloads the screen, like `r` |
| `refresh proxmox [provider]` | Reads every Proxmox provider again now, or only the one named. Nothing changes on the cluster |
| `deploy <app> <environment>` | Starts the deployment wizard |
| `rollback <app> <environment>` | Reviews a rollback |

A node can be named by its ID, its exact name, or a prefix that matches only one node.

## Sessions on a node

`s` opens a shell on the node, `d` opens lazydocker, and `/ ssh <node> btop` or `/ ssh <node> tmux` open those tools. The TUI hands the terminal to the session and takes it back when the session ends, then tells you the exit code.

- The node needs the `node.ssh` capability.
- lazydocker needs Docker on the node and lazydocker installed there. SuperMgmt never installs it; if it is missing, the status line links to its installation guide.
- While a session is starting or ending, the TUI ignores your keys, so quitting cannot leave a session open.

## Deploying and rolling back

`/ deploy <app> <environment>` walks you through a deployment:

1. **Commit:** the full commit SHA that CI built (40 hex characters, or 64 for a SHA-256 repository).
2. **Images:** one or more `service=sha256:<digest>` pairs, separated by commas. Each digest is 64 hex characters.
3. **Review:** the app, target, commit and images. Nothing has been sent yet.

Confirming the review records the deployment. The daemon then checks CI for that commit, freezes the plan and, when policy asks for it, waits for approval. A wrong answer asks the same question again with the reason; `esc` cancels at any step. Follow the deployment on Deployments (`9`).

`/ rollback <app> <environment>` goes straight to a review: which deployment it replaces and the known-good deployment it restores. Policy may ask for approval before it runs. See [Deployments](deployments.md) for how deployments and rollbacks work.

## What the TUI does not do

- **It does not edit configuration.** Providers and Settings are read-only. Add nodes with `sm nodes add`, apps with `sm apps create`, and change the rest in the configuration file ([Configuration](configuration.md)).
- **It does not install software on your nodes.** Setup creates a user, files and a scoped sudoers entry; tools such as lazydocker are yours to install ([Providers](providers.md)).

## The screens in the test suite

The TUI's tests render every screen with fixture data and compare it, character by character, with a stored frame. Those frames are the most faithful picture of the TUI short of running it:

- [Dashboard, 80×24](../internal/tui/testdata/dashboard_80x24.golden)
- [Resources with the detail pane, 120×30](../internal/tui/testdata/resources_120x30.golden)
- [Approvals, 120×30](../internal/tui/testdata/approvals_120x30.golden)
- [A restart plan waiting for confirmation, 80×24](../internal/tui/testdata/confirm_restart_80x24.golden)
- [Command palette, 80×24](../internal/tui/testdata/palette_80x24.golden)
- [Deployment timeline, 80×24](../internal/tui/testdata/m4_nav_deployment_80x24.golden)
- [Help, 80×24](../internal/tui/testdata/help_80x24.golden)

The full set is in [`internal/tui/testdata/`](../internal/tui/testdata). The names, IDs and hashes in them are fixtures, not a real inventory.

## References

- Keys and screens: `internal/tui/model.go` (global keys and screen list), `internal/tui/view.go` (key line, header and status line), `internal/tui/screens.go` (each screen and the Help screen), `internal/tui/action.go` (palette, plans and confirmation), `internal/tui/wizard.go` (deploy and rollback), `internal/tui/handoff.go` (sessions).
- Launch: `internal/cli/tui.go`.
- Related pages: [Getting started](getting-started.md), [Concepts](concepts.md), [CLI reference](cli.md), [Policies and approvals](policies.md).
- Tests: `TestGoldenViews`, `TestM4ScreenGoldens`, `TestGoldenProvidersAndSettings`, `TestKeyboardNavigation`, `TestQuitKeys`, `TestPaletteCommands`, `TestServiceActionNeedsAPlanAndAConfirmation`, `TestPlanDeniedByPolicyCannotBeSubmitted`, `TestApproveSendsThePlanHashOnce`, `TestRejectNeedsAReason`, `TestSetupViaPaletteWarnsAboutDockerAccess`, `TestSessionKeysAreRefusedOnAGuestAndStartNothing`, `TestDeployWizardNeverCreatesWithoutReview`, `TestSmallTerminalExplainsInsteadOfBreaking`.
