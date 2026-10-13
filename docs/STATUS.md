# STATUS — SuperMgmt

> Tracking operativo. Las secciones marcadas con `<!-- pm-sync:* -->` las regenera `/pm sync` — no edites su contenido. El resto es prosa libre.

**Última actualización:** 2026-10-13

---

## Done esta semana

<!-- pm-sync:done-this-week -->
_Pendiente de primera ejecución de `/pm sync`._
<!-- /pm-sync:done-this-week -->

---

## En curso

<!-- pm-sync:in-progress -->
_Pendiente de primera ejecución de `/pm sync`._
<!-- /pm-sync:in-progress -->

---

## Bloqueado / sin actividad

<!-- pm-sync:blocked -->
_Pendiente._
<!-- /pm-sync:blocked -->

---

## Notas humanas

<!-- Añade lo que quieras aquí. `/pm sync` no toca contenido fuera de los markers. -->

- 2026-10-13: M4 (apps, GitHub, deployments) implementado en `feat/m4-apps-deployments`, pendiente de ronda de revisión (W18) y de la ejecución manual contra GitHub real ([checklist](manual-checks/m4-real-github.md)). GitHub, GHCR, attestations y OIDC de Actions están verificados solo contra fakes; ver [compatibility.md](compatibility.md).
- Pendiente humano: ejecución real de M3 (Proxmox) y M4 (GitHub); ver ROADMAP, sección "Human-gated items".
