---
codename: supermgmt
title: M5 — MCP
type: epic
status: active
priority: P1
size: L
issue: null
prs: []
related_issues: [5]
depends_on: [m4-apps-deployments]
supersedes: []
related_specs: []
created: 2026-10-10
updated: 2026-10-13
---

# M5 — MCP

## Contexto / problema

Master spec §31 M5. Exponer el grafo y las acciones a agentes de IA con la misma política que los humanos y sin privilegios extra.

## Scope

**Entra:**
- ADR de la versión de la spec de autorización MCP; columna de estado de cliente MCP (migración 000006; 000005 es de M4).
- Registro de clientes MCP y emisión única de token (§11.2); bridge stdio; streamable HTTP como protected resource (RFC 9728) con AS externo.
- Herramientas de lectura, `infra_plan_action`; herramientas de escritura desactivadas por defecto.
- Tests de seguridad MCP.

**No entra:** hardening de release (M6).

## Criterios de aceptación

### Scenario: lectura sin shell
- **Given** un cliente MCP registrado
- **When** inspecciona nodos, servicios y despliegues
- **Then** obtiene el grafo sin ninguna herramienta de shell

### Scenario: escritura en producción requiere aprobación exacta
- **Given** una escritura en producción que requiere aprobación
- **When** el cliente MCP la envía
- **Then** no se ejecuta hasta que se aprueba ese plan exacto

### Scenario: MCP no puede aprobar
- **Given** una identidad MCP
- **When** intenta aprobar un plan
- **Then** se deniega

## Referencias

Master spec §11.1–11.4, §24, §31 M5.
