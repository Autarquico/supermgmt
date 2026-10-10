---
codename: supermgmt
title: M4 — Apps, GitHub and deployments
type: epic
status: active
priority: P1
size: XL
issue: null
prs: []
related_issues: [4]
depends_on: [m3-proxmox-installer]
supersedes: []
related_specs: []
created: 2026-10-10
updated: 2026-10-10
---

# M4 — Apps, GitHub and deployments

## Contexto / problema

Master spec §31 M4. Despliegues Docker Compose condicionados a CI, con artefactos inmutables, health checks y rollback seguro.

## Scope

**Entra:**
- ADR-0006, 0007, 0008, 0010, 0011 antes del código.
- Migración 000004 (repositorios, apps, app_targets, artifacts, artifact_checks, deployments, deployment_steps, health_checks, webhook_deliveries).
- `internal/providers/github` (checks vía API, OIDC, attestations, webhooks/polling).
- Parser del manifiesto (§19); pipeline Compose cerrado (§20.3); health (§21).
- Máquina de estados de despliegue (§20.1), intents, evidencia y reconciliación (§20.4); ownership y locks (§20.5).
- Wizard, historial y timeline en TUI.

**No entra:** MCP (M5).

## Criterios de aceptación

### Scenario: despliegue del commit/digest exacto que pasó CI
- **Given** un CI verde para un commit con digest atestado
- **When** se crea el despliegue
- **Then** se despliega exactamente ese digest en el nodo gestionado seleccionado

### Scenario: rollback por health check fallido
- **Given** un despliegue cuyo health check falla y rollback declarado seguro
- **When** se verifica
- **Then** vuelve a la versión buena anterior

### Scenario: Compose privilegiado rechazado
- **Given** un compose del repositorio con `privileged: true`
- **When** pasa por el pipeline
- **Then** se rechaza con `COMPOSE_REJECTED`

### Scenario: health URL fuera del nodo rechazada
- **Given** un manifiesto con health check apuntando fuera del nodo
- **When** se valida
- **Then** se rechaza

## Notas técnicas / riesgos

Equivalencia compose-go vs CLI fijada en CI; esquema cerrado completo; codificación byte-exacta de env files de secretos.

## Referencias

Master spec §18–§21, §28, §31 M4, §46.
