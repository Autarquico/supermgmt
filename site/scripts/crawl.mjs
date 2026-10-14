// Crawls the built site (default: dist/, built with the production base) and fails on anything that
// would break or leak at runtime: dead internal links, missing fragments, missing assets, and any
// stylesheet, script, image, font or icon that is loaded from another origin.
import { existsSync, readFileSync, readdirSync, statSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { BASE, SITE } from './sync-docs.mjs';

const NON_FETCH_SCHEMES = /^(mailto|tel|data|javascript|blob):/i;
const NAVIGATION_RELS = new Set(['canonical', 'alternate', 'author', 'license', 'help', 'me']);
const URL_ATTRIBUTES = [
  ['a', 'href', 'link'],
  ['area', 'href', 'link'],
  ['link', 'href', 'asset'],
  ['script', 'src', 'asset'],
  ['img', 'src', 'asset'],
  ['source', 'src', 'asset'],
  ['video', 'src', 'asset'],
  ['audio', 'src', 'asset'],
  ['iframe', 'src', 'asset'],
  ['embed', 'src', 'asset'],
  ['input', 'src', 'asset'],
  ['track', 'src', 'asset'],
  ['object', 'data', 'asset'],
];

const TAG = /<([a-zA-Z][\w:-]*)((?:\s+[^\s=>/]+(?:\s*=\s*(?:"[^"]*"|'[^']*'|[^\s>]+))?)*)\s*\/?>/g;
const ATTRIBUTE = /([^\s=>/]+)(?:\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s>]+)))?/g;
const CSS_URL = /url\(\s*(['"]?)([^'")]+)\1\s*\)|@import\s+(['"])([^'"]+)\3/g;

export function listFiles(dir) {
  return readdirSync(dir).flatMap((name) => {
    const full = path.join(dir, name);
    return statSync(full).isDirectory() ? listFiles(full) : [full];
  });
}

function decodeEntities(value) {
  return value
    .replace(/&amp;/g, '&')
    .replace(/&quot;/g, '"')
    .replace(/&#39;|&#x27;/g, "'")
    .replace(/&lt;/g, '<')
    .replace(/&gt;/g, '>');
}

export function parseTags(html) {
  const tags = [];
  for (const match of html.matchAll(TAG)) {
    const attributes = {};
    for (const attr of match[2].matchAll(ATTRIBUTE)) {
      attributes[attr[1].toLowerCase()] = decodeEntities(attr[2] ?? attr[3] ?? attr[4] ?? '');
    }
    tags.push({ name: match[1].toLowerCase(), attributes });
  }
  return tags;
}

function withoutScriptBodies(html) {
  return html.replace(/<script\b[^>]*>[\s\S]*?<\/script>/gi, (tag) => tag.replace(/>[\s\S]*</, '><'));
}

function styleBodies(html) {
  return [...html.matchAll(/<style\b[^>]*>([\s\S]*?)<\/style>/gi)].map((m) => m[1]);
}

export function cssUrls(css) {
  return [...css.matchAll(CSS_URL)].map((m) => (m[2] ?? m[4]).trim());
}

function pageUrl(distDir, file) {
  const relative = path.relative(distDir, file).split(path.sep).join('/');
  return new URL(BASE + relative.replace(/(^|\/)index\.html$/, '$1'), SITE);
}

function targetFile(distDir, url) {
  const relative = decodeURIComponent(url.pathname.slice(BASE.length));
  if (url.pathname.endsWith('/')) return path.join(distDir, relative, 'index.html');
  return path.join(distDir, relative);
}

function isExternal(url) {
  return url.origin !== new URL(SITE).origin;
}

function startsWithProtocol(value) {
  return /^([a-zA-Z][a-zA-Z0-9+.-]*:|\/\/)/.test(value);
}

export function crawl(distDir) {
  const problems = [];
  const files = listFiles(distDir);
  const pages = files.filter((f) => f.endsWith('.html'));
  const ids = new Map();
  const parsed = new Map();

  for (const file of pages) {
    const html = readFileSync(file, 'utf8');
    const tags = parseTags(withoutScriptBodies(html));
    parsed.set(file, { html, tags });
    ids.set(
      file,
      new Set(tags.flatMap((t) => [t.attributes.id, t.name === 'a' ? t.attributes.name : undefined]).filter(Boolean)),
    );
  }

  const checkInternal = (from, raw, kind, url) => {
    if (!url.pathname.startsWith(BASE)) {
      problems.push(`${from}: ${raw} leaves the base ${BASE}`);
      return;
    }
    const looksLikeFile = path.extname(url.pathname) !== '';
    if (!url.pathname.endsWith('/') && !looksLikeFile) {
      problems.push(`${from}: ${raw} lacks the trailing slash`);
      return;
    }
    const target = targetFile(distDir, url);
    if (!existsSync(target) || statSync(target).isDirectory()) {
      problems.push(`${from}: ${raw} does not resolve to a ${kind === 'link' ? 'page' : 'file'}`);
      return;
    }
    if (kind === 'link' && url.hash.length > 1 && target.endsWith('.html')) {
      const fragment = decodeURIComponent(url.hash.slice(1));
      if (!ids.get(target)?.has(fragment)) problems.push(`${from}: ${raw} points at a missing fragment`);
    }
  };

  const checkReference = (file, raw, kind, { runtime }) => {
    const value = raw.trim();
    if (value === '' || NON_FETCH_SCHEMES.test(value)) return;
    const from = path.relative(distDir, file);
    let url;
    try {
      url = new URL(value, pageUrl(distDir, file));
    } catch {
      problems.push(`${from}: ${raw} is not a valid URL`);
      return;
    }
    if (isExternal(url)) {
      if (runtime) problems.push(`${from}: loads ${url.href} from another origin at runtime`);
      return;
    }
    if (startsWithProtocol(value) && url.protocol !== 'https:') problems.push(`${from}: ${raw} is not https`);
    checkInternal(from, raw, kind, url);
  };

  for (const [file, { html, tags }] of parsed) {
    for (const tag of tags) {
      for (const [name, attribute, kind] of URL_ATTRIBUTES) {
        const value = tag.attributes[attribute];
        if (tag.name !== name || value === undefined) continue;
        const rels = (tag.attributes.rel ?? '').toLowerCase().split(/\s+/);
        const navigation = tag.name === 'link' && rels.every((rel) => NAVIGATION_RELS.has(rel));
        if (rels.includes('canonical')) continue;
        checkReference(file, value, kind, { runtime: kind === 'asset' && !navigation });
      }
      if (tag.attributes.srcset) {
        for (const candidate of tag.attributes.srcset.split(',')) {
          checkReference(file, candidate.trim().split(/\s+/)[0], 'asset', { runtime: true });
        }
      }
      if (tag.attributes.style) {
        for (const url of cssUrls(tag.attributes.style)) checkReference(file, url, 'asset', { runtime: true });
      }
    }
    for (const css of styleBodies(html)) {
      for (const url of cssUrls(css)) checkReference(file, url, 'asset', { runtime: true });
    }
  }

  for (const file of files.filter((f) => f.endsWith('.css'))) {
    for (const url of cssUrls(readFileSync(file, 'utf8'))) checkReference(file, url, 'asset', { runtime: true });
  }

  return { pages: pages.length, problems };
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const distDir = path.resolve(process.argv[2] ?? 'dist');
  if (!existsSync(distDir)) {
    console.error(`crawl: ${distDir} does not exist; build the site first`);
    process.exit(2);
  }
  const { pages, problems } = crawl(distDir);
  if (pages === 0) {
    console.error(`crawl: no HTML pages under ${distDir}`);
    process.exit(2);
  }
  for (const problem of problems) console.error(problem);
  console.log(`crawl: ${pages} pages, ${problems.length} problems`);
  process.exit(problems.length === 0 ? 0 : 1);
}
