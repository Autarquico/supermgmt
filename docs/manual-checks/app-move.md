# Manual checks: moving an app to another node, on real hosts

**Status: NOT RUN.** Moving an app was verified only against simulated nodes and fixture daemons. The feature stays **experimental** until every row below is done and the results are written in [Project status](../project-status.md). Where a row says "record", write what you saw, even when it differs from the expectation, and fix the code or the docs.

You need two managed SSH nodes with Docker and Compose 5.5.1 in the same environment (call them `old` and `new`), both with the `docker.compose.deploy` capability (`sm nodes get`). You also need two app targets on `old` with a succeeded deployment: `shop` with no named volume, and `blog` with a database service and one named volume holding data you can recognise (a file with a known SHA-256, a symlink, a file with a non-root owner and a mode such as 0640, and a few hundred MiB of other data). Neither target may have a route. Keep a terminal on each node and a client for the app next to the CLI.

## 1. A move without volumes

| # | Check | Expected |
|---|---|---|
| 1.1 | `sm apps move shop prod --to new` | Before approval it prints that the move does not stop the app. The plan is high risk |
| 1.2 | Approve and, while it runs, request the app in a loop (`curl` every second) | No failed request until the end. Record the longest gap |
| 1.3 | `sm apps moves shop prod` | `done`, from `old` to `new`, no volumes |
| 1.4 | `docker ps -a` on both nodes | Running on `new`. On `old` the containers exist and are stopped; nothing was removed |
| 1.5 | `sm apps get shop`, then `sm deployments list` | The target's node is `new`. The destination's deployment has kind `move` and is succeeded |
| 1.6 | The audit log | `app_move.started`, `app_move.committed` |

## 2. A move with a volume

| # | Check | Expected |
|---|---|---|
| 2.1 | `sm apps move blog prod --to new` | A warning that the move stops the app while its data is copied, with the volume, its service and mount. Record whether any estimate of the downtime is given |
| 2.2 | Approve. On `old`, `docker ps` while the copy runs | The containers are stopped before the first byte is copied. Record the time from stop to healthy |
| 2.3 | `sm apps moves blog prod` during the copy | The phase moves through `staged`, `source_stopped`, `data_copied`; the volume goes `importing`, `imported`, `verified` |
| 2.4 | On `new`, compare the volume with the source: `sha256sum`, `stat` owner and mode, the symlink, the number of files, empty directories, sparse files if any | Identical. Record any difference: this is the main unconfirmed point |
| 2.5 | The app serves the recognisable data from `new` | Yes |
| 2.6 | During the copy, watch the daemon's memory and the files it writes (`lsof`, the data directory) | Memory stays flat while hundreds of MiB pass. No volume data on the daemon's disk |
| 2.7 | A volume shared by two services | Copied once. Build it by adding a worker that mounts the same volume |

## 3. Refusals, with nothing changed

| # | Check | Expected |
|---|---|---|
| 3.1 | Move to the node the app already runs on, to an unmanaged node, to a node in another environment | Each is refused with the cause. Both nodes untouched |
| 3.2 | Move a target that has a route in `provisioning`, `failed` or being removed | Refused, naming the route. Nothing changed on either node or in Cloudflare |
| 3.3 | Create a volume on `new` named like the target's (`<project>_data`), then move | Preflight refuses it as a leftover volume. The volume is not adopted or deleted |
| 3.4 | Fill `new`'s Docker root so it cannot hold the volume, then move | Preflight refuses it for space. `old` keeps running |
| 3.5 | Request a deployment or a rollback while a move is open | Refused until the move ends |
| 3.6 | `sm apps move blog prod --to new` again while its job still runs | Refused, naming the phase and job |

## 4. Failure and compensation

| # | Check | Expected |
|---|---|---|
| 4.1 | Kill the SSH connection to `new` (or stop its sshd) after `source_stopped`, restore it | The failed copy is replaced, never merged: the destination containers and the volume the move created are removed, and the import restarts from an empty volume. The final volume matches the source |
| 4.2 | Make the app on `new` fail its health check (a bad health port in a copy of the app) before it ever started | The move ends `rolled_back`; `old` runs and is healthy; on `new` the move's containers and volumes are gone and nothing else was touched |
| 4.3 | Make the app on `new` start and then fail its health check | `new` is stopped first, then `old` is started and healthy. The volumes on `new` are kept and listed in the `app_move.rolled_back` event. A new move to `new` is refused while they exist |
| 4.4 | Make `old` unable to restart during compensation (for example free its port with another process) | The move halts in `compensating_source_started`, `new` stopped and intact, the target blocked |
| 4.5 | `sm apps move blog prod --abandon`, approve | `rolled_back`; both nodes exactly as they were. Run it on a move that is not halted in compensation: refused |
| 4.6 | Restore `old`'s port and run `sm apps move blog prod --to new` on a halted move | It resumes and completes compensation or the forward path from the recorded phase, without copying a verified volume again |
| 4.7 | Kill the daemon at each phase (`staged`, `data_copied`, `started`, after `committed`) and start it again | The job resumes from the recorded phase. After `committed` it only goes forward and ends `done` |

## 5. Cleanup

| # | Check | Expected |
|---|---|---|
| 5.1 | `sm apps move blog prod --cleanup-source`, approve | The containers on `old` are removed; the volumes on `old` remain and are listed. Nothing on `new` changed |
| 5.2 | Run it for a target moved back to `old` | Refused: the target runs there again |
| 5.3 | Start another target with the same Compose project on `old`, then run cleanup | Refused |
| 5.4 | Relabel a project container on `old` with another deployment's label, then run cleanup | Refused |

## 6. MCP

| # | Check | Expected |
|---|---|---|
| 6.1 | From a real MCP client with write tools enabled, call `infra_move_app` for `blog` | The result is `approval_required` with risk `high` and says that the app stops while its volumes are copied. Nothing runs until a person approves |
| 6.2 | Approve, then call `infra_list_app_moves` | The move is listed with its phase, nodes and volumes |
| 6.3 | List the client's tools | No tool cleans up the source or abandons a move |

## 5. Routes

Needs a real Cloudflare account with a zone, and tunnel nodes `old` and `new` ([Expose an app](app-expose-tunnel.md)). Use a throwaway hostname. The target has a public route and an `owners` route.

| # | Check | Expected |
|---|---|---|
| 5.1 | `sm apps move blog prod --to new`, read the plan output | It lists both hostnames and, for a stateful app, the rollback window warning |
| 5.2 | While the move is open, run `sm apps unexpose` and `sm apps expose` on the target, and `sm nodes setup old --tunnel`, rotation and disable on `old` and `new` | Each is refused naming the move |
| 5.3 | Approve and watch `sm apps moves blog prod` | Route states advance `dest_published`, `dns_switched`, `committed`, `source_cleaned`; the move ends `done` |
| 5.4 | In the Cloudflare dashboard, read each DNS record | Same record ID, CNAME to `new`'s tunnel, still proxied, comment unchanged |
| 5.5 | Open both hostnames from outside | Both serve from `new`; the `owners` route still asks for the Access login |
| 5.6 | Read `old`'s tunnel ingress | The rules of the moved routes are gone; rules you added by hand are gone too |
| 5.7 | Delete the `owners` route's Access application before a new move, then move | Refused at request time naming the route |
| 5.8 | Delete the Access application while the move runs, before the repoint | The route is halted, its rule leaves both ingresses, the hostname is not served, the move halts |
| 5.9 | Make `new` fail its health check after the repoint (stateless app) | The records return to `old`'s tunnel, `new`'s rules are withdrawn, `old` serves throughout |
| 5.10 | Same with a stateful app; request the hostname every second during the rollback | Errors from the repoint until `old` is healthy again; then normal. Record the length of the window |
| 5.11 | Block the DNS call so its answer is lost (for example cut the daemon's network right after the PATCH) | Nothing else happens for 2 minutes; then the record is read and the move continues or rolls back from what it shows |
| 5.12 | Resume (`sm apps move blog prod --to new`) a routed move halted with a route in `dns_switched` | It completes or rolls back; do not abandon it (the refusal is not implemented yet) |
| 5.13 | A target with a waiting route (no known-good deployment on a copy) | The route has no DNS during the move; it activates on `new` when the move is `done` |
