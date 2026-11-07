# Manual checks: publishing a node port through Cloudflare Tunnel, on a real account

**Status: NOT RUN.** Publishing a node port was verified only against fakes: a hand-written Cloudflare API fake with fault injection after each mutation, and a fake `cloudflared`. The feature stays **experimental** until every row below is done and the results are written in [Project status](../project-status.md). Where a row says "record", write what you saw, even when it differs from the expectation, and fix the code or the docs.

You need the setup of [Cloudflare Tunnel](cloudflare-tunnel.md) already working: a Cloudflare account with the `cloudflare:` block configured, a tunnel node (`sm nodes get` shows `transport: cloudflare`), `cloudflared` on the daemon host, and a zone you control. You also need something on that node listening on `127.0.0.1:8080` (any web server, deployed however you like), and a second hostname in the zone with no existing DNS record. Use a dashboard session next to the terminal.

## 1. A public route

| # | Check | Expected |
|---|---|---|
| 1.1 | `sm nodes expose <node> --hostname shop.<zone> --port 8080`, approve the plan | The command warns that a public route has no authentication. The plan is high risk. The job ends and `sm nodes routes <node>` shows `active` |
| 1.2 | In the dashboard, the tunnel's public hostnames | The SSH rule, `shop.<zone>` to `http://127.0.0.1:8080`, then the 404 catch-all, in that order. Record any difference |
| 1.3 | In the dashboard, DNS | A proxied CNAME `shop.<zone>` to `<tunnel-id>.cfargotunnel.com` whose comment is `supermgmt:<instance>:route:<route-id>`. No Access application for the hostname |
| 1.4 | `curl -i https://shop.<zone>/` from a machine outside your network | What listens on the port answers. Record the status and whether Cloudflare adds anything in front |
| 1.5 | The audit log | `node_route.exposed` with the node, hostname, port and `public` |

## 2. An owners route

| # | Check | Expected |
|---|---|---|
| 2.1 | `sm nodes expose <node> --hostname admin.<zone> --port 8080 --access owners`, approve | No unauthenticated warning. The plan is medium risk. The route ends `active` |
| 2.2 | In the dashboard, Access applications | One self-hosted application named `supermgmt <instance> route <route-id>` for `admin.<zone>`, with the Owners Allow policy only. The service-token policy is not on it |
| 2.3 | Open `https://admin.<zone>/` in a browser | Cloudflare Access asks for a login. An address in `owner_emails` gets in after the One-time PIN or the provider you set; any other address is denied. Record the login methods offered |
| 2.4 | `curl -i https://admin.<zone>/` with no login | A redirect to the Access login, not the app. The SuperMgmt service token does not open it |

## 3. A port nothing listens on

| # | Check | Expected |
|---|---|---|
| 3.1 | Expose a hostname on a port where nothing listens, approve | The route ends `active`. `curl -i https://<hostname>/` shows a Cloudflare error page. Record the status code |
| 3.2 | Start something on that port | The same URL now answers with no further command |

## 4. Removing a route

| # | Check | Expected |
|---|---|---|
| 4.1 | `sm nodes unexpose <node> --hostname admin.<zone>` on the owners route, approve | The route ends removed. In the audit log and the dashboard history the DNS record goes first, then the rule, and the Access application last. Record the order you can see |
| 4.2 | `dig admin.<zone>` and `curl https://admin.<zone>/` | No record. The hostname is not served. Record how long cached answers last |
| 4.3 | The SSH rule and the other route | Still present. `sm nodes probe` still works |
| 4.4 | Expose the same hostname again | It works: the hostname was released |

## 5. Setup rerun and other writers

| # | Check | Expected |
|---|---|---|
| 5.1 | With an active route, `sm nodes setup <node> --tunnel` | The route's rule is still in the dashboard and the hostname still serves |
| 5.2 | Add a public hostname by hand in the dashboard, then expose another route | The hand-made entry is gone after the expose: Cloudflare replaced the whole list. Record it; this is documented |
| 5.3 | `sm cloudflare rotate-access-token` with an active route | The route's rule survives |
| 5.4 | `sm nodes tunnel disable <node>` with an active route | Refused, listing the route. After unexposing every route it proceeds |

## 6. Refusals and foreign objects

| # | Check | Expected |
|---|---|---|
| 6.1 | Create a CNAME for a hostname by hand, then expose that hostname | The route halts naming the record. The record is untouched. No rule for the hostname remains in the tunnel |
| 6.2 | Expose `evil-<zone-label>.<tld>`, `ssh-x.<zone>`, the node's SSH port, and a port another live route of the node already publishes | Each is refused with the cause. Nothing appears in the dashboard |
| 6.3 | Interrupt the daemon during an expose (kill it after the rule appears), start it again | The job finishes. One rule, at most one Access application and one DNS record |

## 7. MCP

| # | Check | Expected |
|---|---|---|
| 7.1 | From a real MCP client with write tools enabled, call `infra_expose_port` with no access | The result is `approval_required` with risk `high`. No rule, record or application exists until a person approves |
| 7.2 | Approve, then call `infra_list_routes` | The route is listed with access `public` and its phase |
