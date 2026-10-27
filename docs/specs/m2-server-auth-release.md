---
codename: supermgmt
title: M2 — Server/client/auth and release pipeline
type: epic
status: shipped
priority: P0
size: XL
issue: 2
prs: [13]
related_issues: [2]
depends_on: [m1-local-ssh-tui]
supersedes: []
related_specs: []
created: 2026-10-10
updated: 2026-10-27
---

# M2 — Server/client/auth and release pipeline

## Contexto / problema

Master spec §31 M2. Modo servidor con HTTPS y autenticación, cliente remoto, secret store, backup/restore y pipeline de release firmada con instalador.

## Scope

**Entra:**
- ADR-0012 (metadatos de rutas) antes del código.
- Migración 000003 (`sessions`, `api_tokens`, `bootstrap_codes`, `oidc_replay`, `secrets`, `join_tokens`).
- HTTPS (TLS direct/proxy), admin socket, bootstrap code (§11.5, §23.1); OIDC PKCE loopback + device grant; tokens con scopes.
- `internal/secrets` (§10: envelope, rotación, export/import-key offline); `internal/netguard` (§21.1).
- Perfiles de cliente, `sm login`, TUI remota, SSE.
- Release: GoReleaser, checksums, firmas OpenSSH, SBOM, provenance; `install.sh` con canales firmados; `sm install local|server|client`.
- `sm backup create|list|restore --offline` con journal y restore hold (§29).
- Join/enrollment (§13). OpenAPI con check de drift. Guía Cloudflare.

**No entra:** Proxmox (M3), despliegues (M4), MCP (M5).

## Criterios de aceptación

### Scenario: control remoto autenticado
- **Given** un servidor en modo server con OIDC
- **When** el `sm` del portátil hace login y opera
- **Then** funciona sobre HTTPS autenticado y el modo local sigue funcionando sin IdP

### Scenario: instalación por curl|bash
- **Given** una VM Debian/runner limpio
- **When** se ejecuta el bootstrap contra una release firmada
- **Then** se instala en modo server; un archivo o firma manipulados fallan con exit 5

> **Nota (decisión Q11, 2026-10-10):** la puerta de CI es un contenedor Debian con systemd (imagen fijada por digest), no una VM. El criterio "VM Debian limpia" queda **enmendado/diferido**: se informa como no cumplido hasta que pase un job opcional `e2e-install-vm` (QEMU/KVM en el runner) o una ejecución manual en VM registrada en el PR.

### Scenario: backup y restore
- **Given** un backup de un servidor
- **When** se restaura en una VM nueva (con crash inyectado en cada paso del journal)
- **Then** el estado final es consistente y arranca en restore hold

## Notas técnicas / riesgos

La clave real de firma de releases requiere custodia humana: se usa clave de test en CI y queda marcado. Dex como IdP de test.

## Referencias

Master spec §3, §10, §11.5, §13, §21.1, §23, §25, §29, §31 M2, §36, §46 ADR-0012.
