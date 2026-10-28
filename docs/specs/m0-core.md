---
codename: supermgmt
title: M0 — Repository and core
type: epic
status: shipped
priority: P0
size: XL
issue: 1
prs: [8]
related_issues: [1]
depends_on: []
supersedes: []
related_specs: []
created: 2026-10-10
updated: 2026-10-27
---

# M0 — Repository and core

## Contexto / problema

Primer hito del master spec (`docs/spec/SUPERMGMT-SPEC.md` §31 M0). Crea el núcleo sobre el que se apoyan todos los demás hitos: esqueleto del repo, configuración estricta, SQLite y migraciones, entidades de dominio, auditoría, catálogo de acciones y motor de políticas (§11), plan canónico con hashing RFC 8785 (Appendix C), aprobaciones con quorum (§11.4) y motor de jobs durable con fencing (§20.4). Sin esto, ninguna acción posterior puede ser segura ni auditable.

## Scope

**Entra:**
- Módulo Go `github.com/autarquico/supermgmt`, layout de §5 limitado a M0.
- `internal/domain`, `internal/domain/plan`, `internal/errors` (§38), `internal/version`.
- `internal/config` (§8.1–8.4, decodificación estricta, overrides `SUPERMGMT_`, validación).
- `internal/audit` (redacción, correlation IDs, slog, emisor de eventos).
- `migrations/000001_initial.up.sql` + `internal/database` (pools, migrate, lock de BD, repos con guard de `spec_revision`).
- `internal/policy` (catálogo §11.2 completo, política por defecto, evaluación §11.3 pasos 1–10, governance y quorum §11.4).
- `internal/jobs` (claim + revalidación, lease_generation, intents, resource_locks shared/exclusive, retry classes, takeover, interfaz de reconciliador; ADR-0013).
- `internal/app` (plans create/submit, approvals, governance, revalidator, lock planner).
- CLI offline: `sm version`, `sm completion`, `sm config validate`, `sm doctor --offline`.
- ADRs 0001–0005 y 0013; índice con 0006–0012 reservados.
- CI (fmt, vet, golangci-lint, test macOS+Linux, race, tidy, generate drift, cross-build ×4, govulncheck), CodeQL, dependency-review, Dependabot.
- Documentos de §27 con estado honesto (pre-alpha; solo M0 marcado como implementado).

**No entra:**
- Daemon, socket, API, TUI, SSH (M1). Secretos, auth, release (M2). Proxmox (M3). Despliegues (M4). MCP (M5).
- Acciones `direct` y `control_plane.apply` (llegan con la API en M1).

## Criterios de aceptación

### Scenario: build, vet, lint y tests
- **Given** el repo en la rama del hito
- **When** se ejecutan `go test ./...`, `go vet ./...` y `make lint`
- **Then** todos pasan en macOS y Linux, también con `-race`

### Scenario: los ejemplos de configuración validan
- **Given** `examples/config.yaml`, `examples/policies.yaml` y los bloques YAML de la spec (§8.2, §8.2.1, §8.3, §11.2, §11.6)
- **When** se ejecuta `sm config validate` / el test de ejemplos
- **Then** validan; y un campo desconocido falla con exit 2 indicando la ruta

### Scenario: las migraciones crean una BD limpia
- **Given** un directorio vacío
- **When** se aplican las migraciones embebidas
- **Then** el esquema coincide con el snapshot, re-aplicar es no-op y una BD más nueva que el binario se rechaza

### Scenario: la política cubre cada paso de §11.3
- **Given** el motor de políticas
- **When** se ejecutan los tests de pasos, propiedad y fuzz
- **Then** cada paso 1–10 tiene casos positivos y negativos, ningún allow anula un deny y añadir targets nunca relaja la decisión

### Scenario: cambiar `spec_revision` invalida la aprobación
- **Given** un plan `node.reboot` sobre un nodo de producción, enviado y aprobado
- **When** cambia el `spec_revision` del nodo antes del claim
- **Then** el job falla con `PLAN_STALE` y evento; una escritura de observación NO lo invalida

### Scenario: fencing de leases
- **Given** un job reclamado por un worker
- **When** otro proceso hace takeover
- **Then** cualquier escritura del worker antiguo afecta 0 filas y los locks se mantienen mientras está `interrupted`

## Notas técnicas / riesgos

- SQLite: `modernc.org/sqlite`, WAL, `synchronous=FULL`, `_txlock=immediate`, un escritor; tablas STRICT con CHECKs; triggers append-only en `events` (ADR-0001).
- JCS propio restringido a enteros (claves ordenadas por UTF-16, escape ES6); vectores RFC 8785 y fuzz.
- `go.mod` lo gestiona solo el architect.
- Riesgo: tamaño del PR; mitigado con revisión por tarea y tabla criterio→test.

## Tasks (no autoritativo — el board manda)

- [ ] T0 bootstrap + contratos · [ ] T13 ADRs · [ ] T1 dominio/errores/versión · [ ] T11 CI/tooling
- [ ] T2 config · [ ] T3 audit · [ ] T4 BD · [ ] T5 policy · [ ] T6 plan/JCS
- [ ] T7 jobs · [ ] T8 app · [ ] T9 CLI · [ ] T10 QA · [ ] T12 docs

## Referencias

`docs/spec/SUPERMGMT-SPEC.md` §5, §6, §8–§11, §20.4–§20.5, §26, §31 M0, §32, §37, §38, §41, Appendix C, Appendix E.
