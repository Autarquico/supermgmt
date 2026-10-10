# ADR-0014: Local API transport and daemon lifecycle

- Status: Accepted
- Spec: §2.1.1, §4, §11.1, §11.5, §23, §38; ADR-0005

## Context

M1 introduces the resident daemon that owns the database (ADR-0005) and serves `/api/v1` on a Unix socket to the CLI and the TUI. The spec fixes the socket location and peer-credential authentication, the lock rules and the envelope. It leaves open several mechanisms: the wire protocol, how idempotent responses are reproduced byte for byte, when an idle daemon may exit, and how a client starts one.

## Decision

### Protocol

- HTTP/1.1 with the JSON envelopes of §23 on the Unix socket. The shared DTOs, headers and paths live in `internal/api/wire`.
- Routing uses the stdlib `ServeMux` with method + pattern routes.

### Peer credentials, both directions

- **Daemon side.** The daemon reads the peer UID in `ConnContext`: Linux `SO_PEERCRED`, darwin `LOCAL_PEERCRED` (the mechanism behind `getpeereid`). A UID mismatch **or a lookup error** closes the connection before any byte is read (fail closed).
- **Client side.** The client checks its own connected fd the same way before its first request, so it never talks to another user's listener.
- Any `Authorization` header returns 401 `UNAUTHENTICATED` until MCP tokens arrive (M5).
- The caller is the `human` identity `local:<uid>` with credential kind `local_socket`, bound to `admin` (§11.5).

### Routes

- The route→action table in `internal/api/routes.go` maps every route to exactly **one** catalog action or one `exempt:*` entry. A Go test enforces it.
- Dynamic verbs become literal routes: `…/actions/start|stop|restart`. Any other verb returns 404.

### Idempotency

- **Request identity:** `SHA-256(method ‖ route pattern ‖ concrete path ‖ If-Match ‖ raw body)`.
- **One transaction.** The app write path receives a `Responder`. Inside the single SQLite write transaction (§23) it produces the mutation, the final HTTP status and the **exact wire envelope bytes**, and commits all three together.
- **Replay** returns the stored status and bytes with `Idempotent-Replayed: true`.
- **Mismatch:** the same key with a different identity returns 409 `CONFLICT`/`IDEMPOTENCY_MISMATCH`.
- A rolled-back mutation stores nothing.
- `Idempotency-Key` is required on every POST, PATCH and DELETE, except the read-only `POST /nodes/ssh/host-key` and `GET /presence`.

### Residency

- **Presence:** long-lived clients (the TUI, `sm jobs --watch`) hold `GET /api/v1/presence` open (`exempt:self`) and reconnect with backoff.
- **In-flight:** one-shot CLI requests count as in-flight while they run.
- **Active work:** any job not in `succeeded`, `failed` or `cancelled`, including `queued`, `awaiting_approval` and `interrupted` (§2.1.1).
- **Idle exit:** the idle timer runs only while presence, in-flight and active work are all zero. It resets on any change, and at `daemon.idle_exit` the daemon shuts down gracefully.
- The per-node focus lease is unrelated to residency.

### Autostart, locks and socket

- **Autostart.** A client that finds no daemon spawns `os.Executable() daemon`: new session (`Setsid`), stdio to `<state>/daemon.log`. It then polls the socket for 5 s.
- **Losing daemon.** A daemon that loses the lock race exits with code 2 and prints nothing; the offline commands keep exit code 4 (M0).
- **Locks** follow §2.1.1:
  - the canonical DB path comes from `realpath(parent)`;
  - the socket directory must pass `lstat`: a real directory, owned by the daemon UID, mode exactly 0700;
  - umask 0177;
  - a `sun_path` overflow is an explicit error;
  - the PID is written in both lock files.

## Consequences

- Peer-credential refusal of another user can only be tested where a second UID exists: Linux CI. macOS relies on the same-UID test plus a manual check.
- Response bytes are stored for 24h per key, so a replay after a crash between commit and response is exact.
- A daemon stays resident while any job awaits approval, by design (§2.1.1).
