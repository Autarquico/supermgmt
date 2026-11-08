# STATUS — SuperMgmt

> Tracking operativo. Las secciones marcadas con `<!-- pm-sync:* -->` las regenera `/pm sync` — no edites su contenido. El resto es prosa libre.

**Última actualización:** 2026-10-13

---

## Done esta semana

<!-- pm-sync:done-this-week -->
- #42 flake: TestHandoffWithMissingSSHShowsErrorAndEndsSessionAsLaunchFailed — sm did not exit after q (macOS PTY loop)
- #43 flake: TestKeyProducesAFrameWithinBudgetWhileADaemonRouteHangs — 70 ms over a 50 ms budget (macOS PTY loop)
- #44 flake: TestFixturesSetup_AdminRootRunsWithoutSudo — systemctl was not found on the node (debian13)
- #52 Move an app target to another node
- #56 Move an app target's Cloudflare routes with it
- #68 appliance: the proxmox-lxc installer fails or degrades on a real PVE 9.1 host
- #69 tunnel: enrollment and re-enable get stuck or fail on a real account
- #75 Retire app move
- #76 Routes publish a node port
- #77 Retire deployments, apps and the GitHub connector
- #83 MCP drives what sm operates: reads, jobs and default grants
<!-- /pm-sync:done-this-week -->

---

## En curso

<!-- pm-sync:in-progress -->
- #85 sm mcp reaches a server: MCP client tokens over HTTPS
<!-- /pm-sync:in-progress -->

---

## Bloqueado / sin actividad

<!-- pm-sync:blocked -->
_(nada)_
<!-- /pm-sync:blocked -->

---

## Notas humanas

<!-- Añade lo que quieras aquí. `/pm sync` no toca contenido fuera de los markers. -->

- 2026-10-13: M5 (MCP) implementado en `feat/m5-mcp`, pendiente de revisión (W10) y del checklist manual [m5-real-mcp-clients.md](manual-checks/m5-real-mcp-clients.md). Verificado solo con el cliente del SDK de Go, goldens JSON-RPC escritos a mano y un servidor de autorización falso: ningún cliente MCP real ni servidor de autorización real (incl. RFC 8707 `resource`) se ha usado. `e2e-mcp` necesita Docker y no se ejecutó al escribir esto.
- Pendiente humano: ejecución real de M3 (Proxmox), M4 (GitHub) y M5 (clientes MCP y servidor de autorización reales); ver ROADMAP, sección "Human-gated items".
