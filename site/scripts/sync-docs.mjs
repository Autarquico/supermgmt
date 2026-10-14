// Copies the public pages listed in docs/public-pages.txt into the Starlight
// content folder, adapting them for the website. docs/*.md stays the only source.
import { existsSync, mkdirSync, readFileSync, rmSync, statSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

export const SITE = 'https://autarquico.github.io';
export const BASE = '/supermgmt/';
export const REPO_BLOB_URL = 'https://github.com/autarquico/supermgmt/blob/main/';
export const REPO_TREE_URL = 'https://github.com/autarquico/supermgmt/tree/main/';

const scriptDir = path.dirname(fileURLToPath(import.meta.url));
const repoRoot = path.resolve(scriptDir, '..', '..');
const outputDir = path.join(repoRoot, 'site', 'src', 'content', 'docs');
const MANIFEST_PATH = 'docs/public-pages.txt';

export function routeFor(slug, base = BASE) {
  return `${base}${slug}/`;
}

export function slugOf(file) {
  return file.replace(/\.md$/, '');
}

export function parseManifest(text) {
  const sections = [];
  const seen = new Set();
  text.split('\n').forEach((raw, index) => {
    const line = raw.trim();
    if (line === '' || line.startsWith('#')) return;
    const where = `${MANIFEST_PATH}:${index + 1}`;
    const header = line.match(/^\[(.+)\]$/);
    if (header) {
      sections.push({ label: header[1], files: [] });
      return;
    }
    if (sections.length === 0) throw new Error(`${where}: page "${line}" before any [Section]`);
    if (!/^[A-Za-z0-9_-]+\.md$/.test(line)) throw new Error(`${where}: "${line}" must be a flat docs/*.md file name`);
    if (seen.has(line)) throw new Error(`${where}: "${line}" is listed twice`);
    seen.add(line);
    sections.at(-1).files.push(line);
  });
  return sections;
}

function fenceOpening(line) {
  const match = line.match(/^ {0,3}(`{3,}|~{3,})/);
  return match ? match[1] : null;
}

// Calls visit(line, inCode) for every line; visit returns the (possibly new) line,
// or null to drop it.
function mapLines(markdown, visit) {
  let fence = null;
  return markdown
    .split('\n')
    .map((line) => {
      const marker = fenceOpening(line);
      if (fence) {
        if (marker && marker[0] === fence[0] && marker.length >= fence.length) fence = null;
        return visit(line, true);
      }
      if (marker) {
        fence = marker;
        return visit(line, true);
      }
      return visit(line, false);
    })
    .filter((line) => line !== null)
    .join('\n');
}

function mapOutsideInlineCode(line, transform) {
  return line
    .split(/(`+[^`]*`+)/)
    .map((part, index) => (index % 2 === 1 ? part : transform(part)))
    .join('');
}

function extractTitle(markdown, file) {
  let title = null;
  const body = mapLines(markdown, (line, inCode) => {
    const heading = inCode ? null : line.match(/^# +(.+?) *#*$/);
    if (!heading) return line;
    if (title === null) {
      title = heading[1].replaceAll('`', '');
      return null;
    }
    return `#${line}`;
  });
  if (title === null) throw new Error(`${file}: no top-level "# " heading to use as the page title`);
  return { title, body };
}

function rewriteDestination(destination, { file, publicFiles, base, kindOf }) {
  if (destination.startsWith('#') || /^[a-z][a-z0-9+.-]*:/i.test(destination)) return destination;
  const hashAt = destination.indexOf('#');
  const target = hashAt === -1 ? destination : destination.slice(0, hashAt);
  const hash = hashAt === -1 ? '' : destination.slice(hashAt);
  const repoPath = path.posix.normalize(path.posix.join('docs', target));
  if (repoPath.startsWith('..')) throw new Error(`docs/${file}: link "${destination}" leaves the repository`);
  const kind = kindOf(repoPath);
  if (kind === null) throw new Error(`docs/${file}: link "${destination}" points to ${repoPath}, which does not exist`);
  const publicFile = repoPath.startsWith('docs/') ? repoPath.slice('docs/'.length) : null;
  if (publicFile !== null && publicFiles.has(publicFile)) return `${routeFor(slugOf(publicFile), base)}${hash}`;
  return `${kind === 'dir' ? REPO_TREE_URL : REPO_BLOB_URL}${repoPath}${hash}`;
}

function rewriteLinks(markdown, context) {
  return mapLines(markdown, (line, inCode) => {
    if (inCode) return line;
    const definition = line.match(/^( {0,3}\[[^\]]+\]:\s*)(\S+)(.*)$/);
    if (definition) return `${definition[1]}${rewriteDestination(definition[2], context)}${definition[3]}`;
    return mapOutsideInlineCode(line, (text) =>
      text.replace(/\]\(([^)\s<>]+)/g, (_, destination) => `](${rewriteDestination(destination, context)}`),
    );
  });
}

const TABLE_REGION_OPEN = '<div class="table-scroll" tabindex="0" role="region" aria-label="Table">';

// Wraps each Markdown table (outside code) in a focusable, labelled scroll region so keyboard users
// can scroll wide tables; the blank lines keep the table parsed as Markdown inside the HTML block.
function wrapTables(markdown) {
  const out = [];
  let inTable = false;
  mapLines(markdown, (line, inCode) => {
    const isRow = !inCode && /^ {0,3}\|/.test(line);
    if (isRow && !inTable) out.push(TABLE_REGION_OPEN, '');
    if (!isRow && inTable) out.push('', '</div>');
    inTable = isRow;
    out.push(line);
    return line;
  });
  if (inTable) out.push('', '</div>');
  return out.join('\n');
}

export function transformPage({ file, source, publicFiles, base = BASE, kindOf }) {
  if (source.startsWith('---')) throw new Error(`docs/${file}: front matter is not expected in public pages`);
  const { title, body } = extractTitle(source, `docs/${file}`);
  const rewritten = wrapTables(rewriteLinks(body, { file, publicFiles, base, kindOf }));
  return `---\ntitle: ${JSON.stringify(title)}\n---\n${rewritten.replace(/^\n+/, '\n')}`;
}

function kindOnDisk(root) {
  return (repoPath) => {
    const absolute = path.join(root, repoPath);
    if (!existsSync(absolute)) return null;
    return statSync(absolute).isDirectory() ? 'dir' : 'file';
  };
}

export function syncDocs({ root = repoRoot, out = outputDir, base = BASE } = {}) {
  const manifest = parseManifest(readFileSync(path.join(root, MANIFEST_PATH), 'utf8'));
  const files = manifest.flatMap((section) => section.files);
  const publicFiles = new Set(files);
  const kindOf = kindOnDisk(root);

  const pages = files.map((file) => {
    const sourcePath = path.join(root, 'docs', file);
    if (!existsSync(sourcePath)) throw new Error(`${MANIFEST_PATH}: ${file} is listed but docs/${file} does not exist`);
    return { file, content: transformPage({ file, source: readFileSync(sourcePath, 'utf8'), publicFiles, base, kindOf }) };
  });

  rmSync(out, { recursive: true, force: true });
  mkdirSync(out, { recursive: true });
  for (const { file, content } of pages) writeFileSync(path.join(out, file), content);
  return files;
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const files = syncDocs();
  console.log(`sync-docs: ${files.length} public pages copied to site/src/content/docs`);
}
