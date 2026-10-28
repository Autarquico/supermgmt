# STATUS — SuperMgmt

> Tracking operativo. Las secciones marcadas con `<!-- pm-sync:* -->` las regenera `/pm sync` — no edites su contenido. El resto es prosa libre.

**Última actualización:** 2026-10-13

---

## Done esta semana

<!-- pm-sync:done-this-week -->
_(nada)_
<!-- /pm-sync:done-this-week -->

---

## En curso

<!-- pm-sync:in-progress -->
- #31 Reach SSH nodes through Cloudflare Tunnel
<!-- /pm-sync:in-progress -->

---

## Bloqueado / sin actividad

<!-- pm-sync:blocked -->
_(nada)_
<!-- /pm-sync:blocked -->

---

## Notas humanas

<!-- Añade lo que quieras aquí. `/pm sync` no toca contenido fuera de los markers. -->

- 2026-10-13: M4 (apps, GitHub, deployments) implementado en `feat/m4-apps-deployments`, pendiente de ronda de revisión (W18) y de la ejecución manual contra GitHub real ([checklist](manual-checks/m4-real-github.md)). GitHub, GHCR, attestations y OIDC de Actions están verificados solo contra fakes; ver [compatibility.md](compatibility.md).
- 2026-10-13: M5 (MCP) implementado en `feat/m5-mcp`, pendiente de revisión (W10) y del checklist manual [m5-real-mcp-clients.md](manual-checks/m5-real-mcp-clients.md). Verificado solo con el cliente del SDK de Go, goldens JSON-RPC escritos a mano y un servidor de autorización falso: ningún cliente MCP real ni servidor de autorización real (incl. RFC 8707 `resource`) se ha usado. `e2e-mcp` necesita Docker y no se ejecutó al escribir esto.
- Pendiente humano: ejecución real de M3 (Proxmox), M4 (GitHub) y M5 (clientes MCP y servidor de autorización reales); ver ROADMAP, sección "Human-gated items".
