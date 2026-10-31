# ADR-0040: Exposing apps through the node's Cloudflare Tunnel

- Status: Proposed
- Spec: spec `docs/specs/app-expose-tunnel.md`; ADR-0029, ADR-0037, ADR-0039

## Context

ADR-0037 gives a node one Cloudflare Tunnel whose ingress is exactly one SSH rule plus the 404 catch-all, and every setup rewrites it to that. A deployed app publishes host ports, but the only way to reach them through the tunnel is to edit the tunnel, Access and DNS by hand, and the next setup erases those edits.

## Decision

### Routes are records; the ingress is derived

- `sm apps expose <app> <env> --hostname --service --port [--access public|owners]` writes an `app_routes` row for the app target.
- The node's ingress is never edited rule by rule. One function derives it from the node's state: the SSH rule, one `http://127.0.0.1:<port>` rule per live route in hostname order, then the 404 catch-all.
- Every writer puts the derived list under the instance Cloudflare lock, recomputing it after acquiring the lock: setup, enable, rotation, disable, expose and unexpose. Cloudflare replaces the whole list on each write, so writers must be serialised and must all agree on the list.
- Writes made from the dashboard are lost on the next write, as under ADR-0037.

### Same order and adoption as SSH

- Expose: ingress rule, then the Access application (only for `owners`), then a proxied CNAME to the tunnel, last.
- Unexpose removes the DNS record, then the ingress rule, and the Access application last, so a hostname still reachable through cached DNS is never served unprotected.
- Each route freezes the account, zone, instance, tunnel and tunnel generation at admission, and halts if any of them changed.
- A `provisioning` phase, written only by the route's own job under the ingress lock after its DNS preflight, records the intent before the first ingress write, and the derived list includes that route from then on, so a crash between the write and its record leaves no rule that another writer can drop or that removal cannot find.
- Each route has its own phases, halt and resume, and IDs written once, as `tunnel_operations` does. Objects are adopted only by their marker (`supermgmt:<instance>:route:<id>`) and only if they were created after the phase started.
- Every DNS record for the hostname is checked on every run, including resumes: marker, proxied CNAME, frozen tunnel. A record without the marker halts the route and is never adopted, replaced or deleted.
- Hostnames are lowercased and must sit under the zone on a label boundary. The `ssh-` first-label namespace is reserved for node SSH hostnames.

### Only healthy versions are published

- A route activates only while the target's newest known-good deployment publishes the port over TCP on `127.0.0.1` or `0.0.0.0`.
- A route requested earlier stays `pending`. A deployment that settles as succeeded schedules its target's pending routes.
- A deployment or rollback that would drop a routed port, in its forward or its automatic-rollback model, is refused at request time and checked again under the target's execution lock. A route therefore never points at a port the current version does not publish.

### Access

- `public` is the default: the CLI, the plan risk (high) and the docs say plainly that the route is unauthenticated.
- `owners` puts a self-hosted Access application on the hostname with only the instance's Owners Allow policy. The service-token policy guards SSH for the daemon and is not reused for apps.

### What stays out

- Route edits in place.
- Other zones, wildcard hostnames and non-HTTP origins.
- Drift reconciliation of route objects.
- Moving routes between nodes, which belongs to `app-move`.
- Disabling the tunnel is refused while the node has routes.

## Consequences

- A tunnel node can publish an app with one command and no inbound port.
- SuperMgmt owns the tunnel ingress outright: hand edits in the dashboard do not survive.
- A public route exposes the app as is, and the app's own authentication is the operator's responsibility.
- Tested against fakes only. The feature is experimental until `docs/manual-checks/app-expose-tunnel.md` has passed with a real account.
