---
codename: supermgmt
title: M1 — Local daemon, SSH, TUI alpha
type: epic
status: active
priority: P0
size: XL
issue: null
prs: []
related_issues: [7]
depends_on: [m0-core]
supersedes: []
related_specs: []
created: 2026-10-10
updated: 2026-10-10
---

# M1 — Local daemon, SSH, TUI alpha

## Contexto / problema

Master spec §31 M1. Primer SuperMgmt usable: daemon local dueño del estado, API sobre socket Unix, gestión agentless de nodos por SSH, descubrimiento de systemd y Docker, y TUI.

## Scope

**Entra:**
- ADR-0009 (job `node.setup`) antes del código.
- Migración 000002 (`instances`, `settings`, `node_addresses`, `idempotency_records`).
- `internal/daemon` (locks de BD y socket, peer-cred mutuo, idle exit, autostart) — §2.1.1.
- API sobre socket con mapa ruta→acción; `internal/client`; acciones `direct` y `control_plane.apply`.
- `internal/transport/ssh` (plantillas, validadores, pool persistente, backoff) — §12; providers `local` y `ssh`; discovery.
- Runtimes `systemd` y `docker` (§16–17); service start/stop/restart como jobs `non_retryable`; reconcilers con evidencia.
- TUI Bubble Tea: dashboard, nodo, servicios, logs, jobs, approvals; handoff SSH interactivo.

**No entra:** HTTPS/auth remoto (M2), Proxmox (M3), despliegues (M4), MCP (M5).

## Criterios de aceptación

### Scenario: gestionar dos nodos sin agente
- **Given** dos nodos Linux de fixture accesibles por SSH con host keys fijadas
- **When** se añaden, sondean y listan
- **Then** se descubren systemd/Docker y sus servicios sin instalar agente

### Scenario: un nodo offline no congela la TUI
- **Given** un nodo inalcanzable entre los gestionados
- **When** la TUI refresca
- **Then** el resto sigue respondiendo (<50 ms por tecla) y el nodo muestra estado de error/stale

### Scenario: restart en producción espera aprobación
- **Given** un servicio en un nodo de un entorno production
- **When** se pide un restart
- **Then** queda en Approvals hasta aprobarse en la TUI

### Scenario: daemon matado a mitad de restart
- **Given** un restart en ejecución
- **When** se mata el daemon
- **Then** el job queda `interrupted` y el reconciliador lo resuelve con evidencia (InvocationID)

## Notas técnicas / riesgos

Peer-cred macOS (`getpeereid`) vs Linux (`SO_PEERCRED`); prueba de otro usuario solo en CI Linux. Fixtures Docker: Debian con systemd PID 1 + sshd + dind.

## Referencias

Master spec §2.1.1, §12, §14, §16, §17, §20.4, §22, §23, §31 M1, §46 ADR-0009.
