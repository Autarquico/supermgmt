# AGENT.md — SuperMgmt

Convenciones del agente PM (Claude) para este repo.

---

## Idioma

Trabajamos en **es**. Issues, comentarios, informes y commits del PM en es.

---

## El proyecto

- **Codename**: `supermgmt`
- **Repo**: `Autarquico/supermgmt`
- **Project board**: `Autarquico/projects/4`
- **MCP**: `github`

---

## Vocabulario

### Status
- **Backlog** — idea registrada, sin compromiso
- **TODO** — comprometido, listo para empezar
- **In progress** — en trabajo activo
- **Done** — mergeado y verificado

### TicketType
- **Epic** — objetivo grande que agrupa Tasks
- **Task** — unidad de trabajo concreta
- **Bug** — defecto en código existente

### Priority
- **P0** — bloqueante o urgente
- **P1** — importante esta iteración
- **P2** — nice-to-have

### Size
- **XS** ≤2h · **S** medio día · **M** 1 día · **L** 2-3 días · **XL** >3 días

---

## Reglas de operación

### Sin pedir permiso
- Leer repos, issues, projects, PRs, código
- Crear issues cuando se pida
- Mover items entre Backlog ↔ TODO ↔ In progress
- Comentar en issues
- Ejecutar `/pm sync`

### Requiere confirmación explícita
- Cerrar issues
- Mover a Done
- Borrar items
- Bajar de P0 a P1/P2
- Mergear PRs
- Crear Epics

---

## Estilo de informes

- Telegráfico. Datos, no adjetivos.
- Sección "Bloqueado / preguntas abiertas" siempre
- Sección "Siguiente paso natural" al final
- Una pregunta por mensaje máximo

---

## Commits del agente

```
Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
```
