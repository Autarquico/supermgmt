# Dependencies and egress

What SuperMgmt is built from, under which licences, and every network destination it can contact. The `sm` binary and the documentation website are covered separately: nothing from the website is part of `sm`. Versions are those of `go.mod`, `Makefile`, `site/package.json` and the workflows at the time of writing; those files win over this page.

## Licences

- **What ships.** Every release archive contains `THIRD_PARTY_LICENSES`, generated from the build info of the compiled `sm` (`go version -m`): each module with its full licence text and any `NOTICE` file. `packaging/release/check.sh` compares the file with each archive's binary before publishing. This file, not the table below, is the authoritative per-module list, indirect modules included.
- **What is allowed.** `make licenses` runs `go-licenses` over `./cmd/sm` and accepts only Apache-2.0, MIT, BSD-2-Clause, BSD-3-Clause, ISC and MPL-2.0 (`ALLOWED_LICENSES` in the `Makefile`; CI job `licenses`). The dependency-review workflow uses the same list.
- **What a person reviewed.** Three modules carry a licence file the classifier cannot name. Each has a reviewed entry in `packaging/release/license-overrides.txt` with the licence, the file and its sha256: `github.com/in-toto/attestation`, `github.com/in-toto/in-toto-golang` and `github.com/cyberphone/json-canonicalization`, all Apache-2.0. A version bump of one of them changes the hash and fails `notices.sh` until the new text is reviewed.
- **What no test decides.** Whether the shipped `THIRD_PARTY_LICENSES` is legally sufficient is a human row of the release checklist, as are the project's own licence and trademark.

### Direct dependencies

Licence families below were read from the licence file of each module in the module cache. They name the family, not an SPDX expression; `THIRD_PARTY_LICENSES` carries the exact texts.

| Module | Version | Used for | Licence |
|---|---|---|---|
| `charm.land/bubbletea/v2`, `bubbles/v2`, `lipgloss/v2` | 2.0.10, 2.2.1, 2.0.6 | Terminal UI | MIT |
| `github.com/spf13/cobra` | 1.10.2 | Command line | Apache-2.0 |
| `modernc.org/sqlite` | 1.60.1 | Database driver (no CGO) | BSD-style |
| `github.com/klauspost/compress` | 1.20.1 | zstd in backup archives | BSD-style |
| `go.yaml.in/yaml/v3` | 3.0.5 | Configuration and manifests | MIT |
| `golang.org/x/crypto`, `x/oauth2`, `x/sys` | 0.57.0, 0.37.0, 0.48.0 | Key derivation, OAuth, system calls | BSD-style |
| `github.com/google/uuid` | 1.6.0 | Identifiers | BSD-style |
| `github.com/compose-spec/compose-go/v2` | 2.15.0 | Compose loader, same code base as the Compose CLI | Apache-2.0 |
| `github.com/coreos/go-oidc/v3` | 3.21.0 | OIDC login | Apache-2.0 |
| `github.com/go-jose/go-jose/v4` | 4.1.4 | JWT verification | Apache-2.0 |
| `github.com/modelcontextprotocol/go-sdk` | 1.8.0 | MCP server | MIT and Apache-2.0 notices in one file |
| `github.com/sigstore/sigstore-go`, `protobuf-specs` | 1.3.0, 0.5.1 | Attestation verification | Apache-2.0 |
| `github.com/theupdateframework/go-tuf/v2` | 2.4.2 | TUF client for the Sigstore and GitHub trusted roots | Apache-2.0 |
| `github.com/secure-systems-lab/go-securesystemslib` | 0.11.0 | DSSE envelopes; imported directly by the GitHub fake (`internal/providers/github/ghfake`) | MIT |
| `github.com/creack/pty` | 1.1.24 | Test code only (terminal handoff tests) | MIT |
| `github.com/google/go-containerregistry` | 0.21.7 | Test code only (`test/e2e/ghsim`, the local registry) | Apache-2.0 |

The last two are imported only by test code, so they are not in the `sm` binary and not in `THIRD_PARTY_LICENSES`.

`cloudflared` is a runtime dependency of the Cloudflare tunnel feature only, not of `sm`: the daemon host needs it to dial tunnel nodes, your own machine for `sm ssh` to them, and each tunnel node gets it from Cloudflare's package repository. It is third-party software, not linked into `sm` and not covered by `THIRD_PARTY_LICENSES`; SuperMgmt does not pin a version on the daemon host, and on the node apt provides whatever version the repository serves.

### Tools pinned outside `go.mod`

Run with `go run <module>@<version>`, or downloaded by a pinned workflow step. Versions at the time of writing; the files named win.

| Tool | Version | Where pinned | Purpose |
|---|---|---|---|
| govulncheck | v1.8.0 | `Makefile` | Vulnerability scan |
| actionlint | v1.7.7 | `Makefile` | Workflow lint |
| vacuum | v0.30.6 | `Makefile` | OpenAPI lint |
| gitleaks | v8.30.1 | `Makefile` | Secret scan of the full history |
| go-licenses | v2.0.1 | `Makefile` | Licence gate |
| GoReleaser | v2.18.2 | `release.yml` | Release build |
| syft | v1.52.0 | `release.yml` | SBOM |
| Docker Compose CLI | 5.5.1 | `test/fixtures/node/Dockerfile`; node requirement in [compatibility.md](compatibility.md#docker-compose-and-node-tools) | Deployments on nodes |

The licences of the tools are not recorded here. They are build-time tools: none is linked into `sm`.

## Egress

SuperMgmt makes no request that you did not configure or trigger, and it has no update check and no telemetry. Evidence: the literal `https://` URLs in non-test Go code are the GitHub API default (`internal/config/github.go`), the Cloudflare API default (`internal/providers/cloudflare/client.go`), the GitHub TUF mirror (`internal/providers/github/trustroot.go`), the GitHub Actions issuer (`internal/providers/github/types.go`) and documentation links; none names a release or an update endpoint. A destination missing from the table below is a defect.

Requests from the control plane to a URL an operator supplies pass the outbound filter (`internal/netguard`: a name is resolved once; metadata, loopback, link-local, multicast and reserved ranges are refused; see [security.md](security.md)). Proxmox endpoints are the exception that allows private ranges, since a PVE host usually sits on one.

| Destination | Made by | Trigger | Off-switch |
|---|---|---|---|
| `github.com/autarquico/supermgmt/releases/download/...` (release archives, `checksums.txt`, signatures, signed channel pointers) | `install.sh` (install and `install.sh upgrade`) and `scripts/join.sh` | A person runs one of them | `SUPERMGMT_RELEASE_BASE_URL` points them at a mirror; `sm install upgrade --binary <file>` installs a local file and downloads nothing |
| `api.github.com`, or the `api_url` of a GitHub Enterprise Server | The control plane | A provider of `type: github` exists and a deployment, a CI watch or a repository listing needs it | Remove the provider. Redirects are followed only to the same origin, at most three hops |
| `tuf-repo-cdn.sigstore.dev` and `tuf-repo.github.com` (TUF metadata for the Sigstore public-good and GitHub trusted roots) | The control plane | Attestation verification of a deployed image digest; a root is refreshed at most every 24 hours and a copy older than 7 days is refused | Do not configure a GitHub provider; an environment without `require_provenance` does not need attestations |
| `token.actions.githubusercontent.com` (JWKS of GitHub Actions OIDC tokens) | The control plane | A GitHub Actions bearer arrives on the HTTPS listener | Leave `github.oidc_audience` and `server.public_url` unset: Actions tokens are then not accepted |
| The `auth.oidc.issuer` (discovery document, token, device authorization and JWKS endpoints) | The control plane | A login through OIDC; discovery runs on first use, not at start | Leave `auth.oidc` unset |
| The `mcp.oauth.jwks_url` and `mcp.oauth.introspection_url` | The control plane | A remote MCP request carrying a bearer token (JWKS is refetched once on an unknown `kid`; introspection is never cached) | `mcp.remote_enabled: false`. The stdio bridge (`sm mcp`) talks only to the daemon's Unix socket |
| A Proxmox VE endpoint (`https://host:8006`) | The control plane | A Proxmox provider exists: sync, power actions, `providers check` | Remove the provider |
| `api.cloudflare.com` | The control plane | A `cloudflare:` block exists and a tunnel job runs (`sm nodes setup --tunnel`, `sm nodes tunnel disable`, `sm cloudflare rotate-access-token`); `sm doctor` with the server running makes read-only calls with the API token if it is stored; reconciliation after `sm admin restore-complete` reads | Remove the `cloudflare:` block. Without the block no Cloudflare call is made |
| `ssh-<node>.<zone>` (the tunnel hostname, served by Cloudflare Access) | The control plane (one HTTPS preflight with the service-token headers) and the `cloudflared` child it starts | Every new connection to a node with the `cloudflare` transport | `sm nodes tunnel disable <node>` returns the node to a direct dial |
| `pkg.cloudflare.com` | `apt-get` on the node | `sm nodes setup <node> --tunnel` installs `cloudflared`, and later when you update the node's packages | `sm nodes tunnel disable <node>` removes the repository if setup installed it |
| Cloudflare's edge | `cloudflared` on the node | While a tunnel node's service runs (a persistent outbound connection) | `sm nodes tunnel disable <node>` |
| Managed nodes, over SSH (port 22 by default) | The control plane | Discovery, node setup, deployments, health checks | Remove the node |
| Container registries named in the Compose file | The node's Docker, never the control plane | A deployment pulls an image; `docker manifest inspect` runs on the node for the disk preflight | Do not deploy |
| URLs of `health.http` checks | `curl` on the node | A deployment's health check | Do not define the check |
| The Proxmox host's template mirror | `pveam download` on the Proxmox host | `sm install proxmox-lxc` when the Debian 13 template is not yet present | Download the template yourself before running the installer |

Inbound, for completeness: the optional GitHub webhook (`POST /api/v1/github/webhook`, HTTPS listener only) and MCP and API clients. Neither is egress.

Not verified: that this list is complete. It was assembled from the configuration reference and from reading the call sites above, not from a packet capture of a running instance.

## Website dependencies

The documentation website is built from `docs/*.md` with [Astro](https://astro.build) and [Starlight](https://starlight.astro.build) in `site/`. None of it is linked into `sm` or shipped in a release archive, and `THIRD_PARTY_LICENSES` does not cover it.

| Package | Version | Used for | Licence |
|---|---|---|---|
| `astro` | 7.3.8 | Static site generator | MIT |
| `@astrojs/starlight` | 0.42.6 | Documentation theme, sidebar, search (Pagefind) | MIT |
| `@fontsource-variable/geist` | 5.3.0 | Body font, self-hosted | OFL-1.1 |
| `@fontsource-variable/geist-mono` | 5.3.0 | Code font, self-hosted | OFL-1.1 |
| `@fontsource/instrument-serif` | 5.3.0 | Heading font, self-hosted | OFL-1.1 |

- **Pinned.** Versions are exact in `site/package.json`, and `site/package-lock.json` pins the whole tree (353 packages, all from `registry.npmjs.org`). Node is pinned in `site/.nvmrc`. Installs run `npm ci --ignore-scripts`, so no package runs an install script.
- **Fonts.** The three fonts are under the SIL Open Font License 1.1, which allows embedding and redistribution. The build copies each font's licence text into the site, under `licenses/fonts/` (`site/scripts/font-licenses.mjs`). OFL-1.1 is not in the general allow-list of the dependency-review workflow; the font packages are exempted by name, with the reason written in `.github/workflows/dependency-review.yml`.
- **The rest of the tree.** The lockfile records mostly MIT, plus Apache-2.0, ISC, BSD, MPL-2.0 and a few others. Platform-specific optional packages of the image library `sharp` carry LGPL-3.0-or-later for the bundled libvips. They run at build time only. Which of them end up installed depends on the build machine; no licence review of these build-time packages was done beyond reading the lockfile.
- **Checked in CI.** The `site` job builds the site and runs `make site-audit`: `npm audit signatures` and `npm audit --omit=dev --audit-level=high`. Dependabot proposes npm updates for `/site`.
- **No third-party requests from the site.** Fonts, scripts and styles are served from the site itself: no analytics, no CDN, no tracking. `make site-check` crawls the built HTML and fails on any resource loaded from another origin (`site/scripts/crawl.mjs`). The crawl does not inspect URLs inside JavaScript. Links to other sites, such as GitHub, are plain links. The website is hosted on GitHub Pages, so GitHub serves it and sees the requests for it.

## References

- Decision records: [ADR-0034](adr/0034-release-hardening-gates.md) licence gate and pinned tools, [ADR-0036](adr/0036-distribution-notices-platform-claims.md) notices, egress inventory and platform claims.
- Binding specification: [`docs/spec/SUPERMGMT-SPEC.md`](spec/SUPERMGMT-SPEC.md), section 41 (no silent phone-home).
- Files: `Makefile` (`licenses`, `site`, `site-check`, `site-audit`), `packaging/release/license-overrides.txt`, `site/package.json`, `site/package-lock.json`, `site/scripts/font-licenses.mjs`, `.github/workflows/dependency-review.yml`.
