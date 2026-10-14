import { readFileSync } from 'node:fs';
import path from 'node:path';
import { routeFor, slugOf } from '../../scripts/sync-docs.mjs';

const STATUS_FILE = 'docs/project-status.md';
const HEADER = ['Claim', 'Scope', 'Evidence', 'Level', 'Limitation'];

export const LEVELS = [
  { name: 'implemented and tested in CI', tone: 'success' },
  { name: 'tested against fakes', tone: 'info' },
  { name: 'configured, not yet run', tone: 'warning' },
  { name: 'not verified', tone: 'muted' },
] as const;

export type Level = (typeof LEVELS)[number];
export type Claim = { claim: string; scope: string; evidence: string; level: Level; limitation: string };
export type Evidence = { href: string; level: Level };
export type Status = { claims: Claim[]; notVerifiedIntro: string; notVerified: string[] };

const escapeHtml = (text: string) =>
  text.replaceAll('&', '&amp;').replaceAll('<', '&lt;').replaceAll('>', '&gt;').replaceAll('"', '&quot;');

function linkHref(destination: string): string | null {
  const match = destination.match(/^([A-Za-z0-9_-]+\.md)(#[\w-]+)?$/);
  if (match) return `${routeFor(slugOf(match[1]))}${match[2] ?? ''}`;
  return /^https:\/\//.test(destination) ? destination : null;
}

// Inline markdown of the status page (code spans, bold, links) to safe HTML.
export function inlineHtml(markdown: string): string {
  return markdown
    .split(/(`[^`]+`)/)
    .map((part) => {
      if (part.startsWith('`')) return `<code>${escapeHtml(part.slice(1, -1))}</code>`;
      return escapeHtml(part)
        .replace(/\*\*([^*]+)\*\*/g, '<strong>$1</strong>')
        .replace(/\[([^\]]+)\]\(([^)\s]+)\)/g, (_, label, destination) => {
          const href = linkHref(destination.replaceAll('&amp;', '&'));
          return href ? `<a href="${escapeHtml(href)}">${label}</a>` : label;
        });
    })
    .join('');
}

function sectionLines(lines: string[], heading: string): string[] {
  const start = lines.indexOf(`## ${heading}`);
  if (start === -1) throw new Error(`${STATUS_FILE}: no "## ${heading}" section`);
  const rest = lines.slice(start + 1);
  const end = rest.findIndex((line) => line.startsWith('## '));
  return end === -1 ? rest : rest.slice(0, end);
}

function cellsOf(row: string): string[] {
  return row.replace(/^\|/, '').replace(/\|$/, '').split('|').map((cell) => cell.trim());
}

function parseClaims(lines: string[]): Claim[] {
  const rows = sectionLines(lines, 'Claims').filter((line) => line.startsWith('|'));
  if (rows.length < 3 || cellsOf(rows[0]).join('|') !== HEADER.join('|')) {
    throw new Error(`${STATUS_FILE}: the claims table must have the columns ${HEADER.join(' | ')}`);
  }
  return rows.slice(2).map((row) => {
    const cells = cellsOf(row);
    if (cells.length !== HEADER.length || cells.some((cell) => cell === '')) {
      throw new Error(`${STATUS_FILE}: malformed claims row: ${row.slice(0, 60)}`);
    }
    const level = LEVELS.find((candidate) => candidate.name === cells[3]);
    if (!level) throw new Error(`${STATUS_FILE}: unknown level "${cells[3]}"`);
    const [claim, scope, evidence, , limitation] = cells;
    return { claim, scope, evidence, level, limitation };
  });
}

function parseNotVerified(lines: string[]) {
  const section = sectionLines(lines, 'Not verified');
  const intro = section.find((line) => line.trim() !== '' && !line.startsWith('- '));
  const items = section.filter((line) => line.startsWith('- ')).map((line) => line.slice(2).trim());
  if (!intro || items.length === 0) throw new Error(`${STATUS_FILE}: the "Not verified" section needs an intro and a list`);
  return { notVerifiedIntro: intro, notVerified: items };
}

export function readStatus(): Status {
  const lines = readFileSync(path.resolve(process.cwd(), '..', STATUS_FILE), 'utf8').split('\n');
  return { claims: parseClaims(lines), ...parseNotVerified(lines) };
}

export const claimAnchor = (index: number) => `claim-${index + 1}`;

export const siteVersion = (): string | undefined => process.env.SITE_VERSION?.trim() || undefined;

// The anchor and level of the landing card of the claim that starts with `claimStart`; fails the build when the status table drops it.
export function evidenceFor(claims: Claim[], claimStart: string): Evidence {
  const index = claims.findIndex((claim) => claim.claim.startsWith(claimStart));
  if (index === -1) throw new Error(`${STATUS_FILE}: no claim starts with "${claimStart}"`);
  return { href: `#${claimAnchor(index)}`, level: claims[index].level };
}
