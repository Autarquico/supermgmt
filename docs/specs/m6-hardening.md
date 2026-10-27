---
codename: supermgmt
title: M6 — Hardening and release
type: epic
status: shipped
priority: P1
size: L
issue: 6
prs: [17]
related_issues: [6]
depends_on: [m5-mcp]
supersedes: []
related_specs: []
created: 2026-10-10
updated: 2026-10-27
---

# M6 — Hardening and release

## Contexto / problema

Master spec §31 M6. Endurecer y preparar la primera release: fuzzing, race, escaneos, documentación completa, matriz de compatibilidad y E2E de instalación/upgrade/restore/uninstall.

## Scope

**Entra:**
- Fuzz de todos los parsers; tests de race; escaneos de seguridad.
- Plan de empaquetado/homebrew; `docs/compatibility.md`.
- Tests de migración desde fixtures de cada commit de milestone en `main` (binarios reales de cada merge, versiones sintéticas; aún no existe ningún tag, ADR-0035).
- Cierre de documentación y barrido del checklist del Appendix E.

**No entra:** módulos post-V1 (§44).

## Criterios de aceptación

### Scenario: E2E en máquina limpia
- **Given** máquinas limpias de la matriz soportada
- **When** se instala, actualiza, restaura y desinstala
- **Then** todo funciona y el proceso de release está documentado

### Scenario: elementos con gate humano marcados
- **Given** Proxmox real, clave de firma real y trademark/licencia
- **When** se prepara la release
- **Then** aparecen como checklist pendiente explícito, nunca como hechos

## Referencias

Master spec §32–§36, §43, Appendix E.
