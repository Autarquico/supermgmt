---
codename: supermgmt
title: M3 — Proxmox provider and appliance installer
type: epic
status: active
priority: P1
size: XL
issue: null
prs: []
related_issues: [3]
depends_on: [m2-server-auth-release]
supersedes: []
related_specs: []
created: 2026-10-10
updated: 2026-10-10
---

# M3 — Proxmox provider and appliance installer

## Contexto / problema

Master spec §31 M3. Descubrimiento de Proxmox y appliance LXC instalado con un solo comando.

## Scope

**Entra:**
- ADR de privilegios PVE y matriz de compatibilidad.
- `internal/providers/proxmox` (discovery, árbol VM/LXC, acciones de energía como jobs `non_retryable` con UPID persistido).
- `sm install proxmox-lxc` (pct/pveam/pvesh/pveum tras interfaces, journal de rollback, transferencia segura del token §3.5).
- `sm install upgrade|uninstall`.

**No entra:** despliegues (M4), MCP (M5).

## Criterios de aceptación

### Scenario: host PVE → LXC funcional (DIFERIDO a PVE real)
- **Given** un host PVE soportado (en CI: API y CLI PVE falsas)
- **When** se ejecuta un solo comando de instalación
- **Then** existe un LXC con SuperMgmt, el cluster está descubierto y `sm login` desde el portátil conecta

### Scenario: rollback del instalador
- **Given** un fallo inyectado en cada paso del instalador
- **When** falla
- **Then** se revierten solo los recursos creados

### Scenario: upgrade N-1 → N
- **Given** una instalación N-1
- **When** se actualiza
- **Then** se hace backup previo automático y el servicio queda sano

## Notas técnicas / riesgos

No hay host Proxmox: la aceptación real queda como checklist manual antes de la primera release y así se marca en ROADMAP/README.

## Referencias

Master spec §2.3, §3.5, §15, §29.3–29.4, §31 M3.
