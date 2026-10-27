---
codename: supermgmt
title: "Project site: landing and documentation"
type: epic
status: shipped
priority: P1
size: L
issue: 19
prs: [20]
related_issues: [19]
depends_on: []
supersedes: []
related_specs: []
created: 2026-10-14
updated: 2026-10-27
---

# Project site: landing and documentation

## Contexto / problema

The code of V1 is done (M0–M6) but the documentation is organised by milestone, leaks internal jargon (milestone codes, SPEC section numbers, finding IDs), has no getting-started path, no TUI guide, no CLI reference and no policy guide, and the project has no website. A new user cannot go from zero to a managed node without reading the README twice; an evaluator cannot find in one place what is verified and what is not. Audit: `.claude/loop/site-and-docs/docs-audit.md`.

## Scope

**Entra:**
- A static site in `site/` (Astro + Starlight) published to GitHub Pages from `main`: a landing page and the documentation.
- `docs/*.md` stays the single source of the documentation (flat, GitHub-readable, checked by `test/docs`).
- New pages: overview, getting started, concepts, verification status, TUI guide, CLI reference (generated from the command tree, drift-checked), policies and approvals.
- Rewrite for users: README (short), security (by topic), architecture (stale lines), and removal of milestone/finding jargon from public pages.
- Landing: what it is, how it works, the trust model, real TUI frames rendered from the TUI golden files, honest status, install/build instructions.
- Design: brief `.claude/design-briefs/base.yml` and `landing.yml` (Instrument Serif / Geist / Geist Mono, Lucide, signal-teal accent, light and dark).

**No entra:**
- Product changes, new features, a custom domain, analytics or any third-party script on the site, translations.
- Internal documents on the public site: STATUS, release checklist, releasing, manual checks, specs, the master spec, individual ADRs (linked to GitHub instead).

## Criterios de aceptación

### Scenario: a new user reaches a managed node from the site
- **Given** a visitor with a Mac or Linux laptop and no prior knowledge
- **When** they follow Getting started on the site
- **Then** every command shown exists in `sm` (checked by a test), and the page states the prerequisites and what works today

### Scenario: an evaluator finds what is verified
- **Given** the landing and the Status page
- **When** an evaluator looks for what is tested against real systems versus fakes
- **Then** one canonical page states it, every claim on the landing links to evidence, and no claim contradicts it

### Scenario: docs stay honest and checked
- **Given** a change to `docs/*.md`
- **When** CI runs
- **Then** `docs-check` still validates cited tests, jobs, links and anchors, public pages contain no milestone codes or finding IDs, and the CLI reference matches the command tree

### Scenario: the site builds and deploys safely
- **Given** a push to `main`
- **When** the site workflow runs
- **Then** the site builds reproducibly from a lockfile, only the Pages deploy job has `pages: write`, actions are pinned by SHA, and no third-party script or font CDN is loaded at runtime

### Scenario: the site is usable and accessible
- **Given** the landing and a docs page
- **When** viewed at 360 px and desktop, light and dark, keyboard only
- **Then** there is no horizontal scroll, contrast meets WCAG AA, and focus is visible

## Notas técnicas / riesgos

- `test/docs` scans only flat `docs/*.md`; the platform table in `docs/compatibility.md`, the generated env table in `docs/configuration.md` and the `[human]` rows must keep their structure.
- npm dependencies are new to the repo: lockfile, pinned versions, Dependabot, dependency review.
- The landing must not claim a release until one exists; it reads status from the docs, not from hand-written copy where possible.

## Referencias

Audit `.claude/loop/site-and-docs/docs-audit.md`; design `~/.claude/design-system.yml`, `.claude/design-briefs/`.
