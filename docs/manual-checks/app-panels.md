# Manual checks: app panels on a real host

**Status: NOT RUN.** App panels were verified against fake nodes, the Docker fixture node and the TUI harness. Where a row says "record", write what you saw, even when it differs from the expectation, and fix the code or the docs.

You need a node with `docker_access` set up, running a real Compose project with at least two services, one with a healthcheck, and an environment variable holding a value you can recognise.

| # | Check | Expected |
|---|---|---|
| 1 | Key `9` in the TUI, or `sm apps list` | The project is an app with its components. Other containers and units are listed under the node, ungrouped |
| 2 | `docker restart` one component twice, then refresh | The restart count rises. The reading time updates |
| 3 | Stop a component | The app shows degraded |
| 4 | Open the app, then `sm apps show <node> <project>` | Components, volumes and ports match `docker compose ps` and `docker inspect`. The secret value appears in neither |
| 5 | Follow a component under steady output, for at least a minute | Lines arrive in order with no loss or repeats compared with `docker logs`. Record the delay |
| 6 | Search for a word in the logs with `/` | Matches are highlighted and the window covered is stated |
| 7 | Log a line such as `password=abc123`, and a PEM block | Both are redacted in follow, search and an MCP client |
| 8 | Restart a component from the panel | The plan and approval appear, and the action is in the audit log |
| 9 | Disconnect the node's network, then open its apps | Last discovery marked stale with its time; live reads and actions say the node cannot be reached |
| 10 | A node without `docker_access` | The node says apps cannot be read and names `sm nodes setup <node> --docker-access`. Nothing changes on the node |
| 11 | Ask an MCP client "is anything failing in `<project>`?" | It uses the app tools and answers from them. Node content is marked untrusted |
| 12 | Open the overview with many containers on a node | Record how long it takes to fill |
