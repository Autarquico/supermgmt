import assert from 'node:assert/strict';
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { afterEach, describe, it } from 'node:test';
import { crawl, cssUrls, parseTags } from './crawl.mjs';

const roots = [];

afterEach(() => {
  while (roots.length > 0) rmSync(roots.pop(), { recursive: true, force: true });
});

function buildDist(files) {
  const root = mkdtempSync(path.join(tmpdir(), 'crawl-'));
  roots.push(root);
  for (const [name, content] of Object.entries(files)) {
    const full = path.join(root, name);
    mkdirSync(path.dirname(full), { recursive: true });
    writeFileSync(full, content);
  }
  return root;
}

const page = (body, head = '') => `<!doctype html><html><head>${head}</head><body>${body}</body></html>`;

function problemsFor(files) {
  const dist = buildDist({ 'index.html': page(''), 'other/index.html': page('<h2 id="here">x</h2>'), ...files });
  return crawl(dist).problems;
}

describe('crawl', () => {
  it('reports nothing for a site whose links, fragments and assets resolve', () => {
    const problems = problemsFor({
      'index.html': page(
        '<a href="/supermgmt/other/#here">ok</a><img src="/supermgmt/logo.svg">',
        '<link rel="stylesheet" href="/supermgmt/site.css">',
      ),
      'logo.svg': '<svg/>',
      'site.css': 'body{background:url(/supermgmt/logo.svg)}',
    });
    assert.deepEqual(problems, []);
  });

  it('reports an internal link without a trailing slash', () => {
    const problems = problemsFor({ 'index.html': page('<a href="/supermgmt/other">x</a>') });
    assert.equal(problems.length, 1);
    assert.match(problems[0], /lacks the trailing slash/);
  });

  it('reports a link to a page that does not exist', () => {
    const problems = problemsFor({ 'index.html': page('<a href="/supermgmt/missing/">x</a>') });
    assert.equal(problems.length, 1);
    assert.match(problems[0], /does not resolve to a page/);
  });

  it('reports a link to a fragment the target page does not define', () => {
    const problems = problemsFor({ 'index.html': page('<a href="/supermgmt/other/#nope">x</a>') });
    assert.equal(problems.length, 1);
    assert.match(problems[0], /missing fragment/);
  });

  it('reports an asset that does not exist', () => {
    const problems = problemsFor({ 'index.html': page('<img src="/supermgmt/gone.png">') });
    assert.equal(problems.length, 1);
    assert.match(problems[0], /does not resolve to a file/);
  });

  it('reports a script loaded from another origin', () => {
    const problems = problemsFor({ 'index.html': page('<script src="https://cdn.example.com/a.js"></script>') });
    assert.equal(problems.length, 1);
    assert.match(problems[0], /another origin at runtime/);
  });

  it('reports a stylesheet loaded from another origin', () => {
    const problems = problemsFor({
      'index.html': page('', '<link rel="stylesheet" href="https://fonts.example.com/f.css">'),
    });
    assert.equal(problems.length, 1);
    assert.match(problems[0], /another origin at runtime/);
  });

  it('reports an external url() in a stylesheet file', () => {
    const problems = problemsFor({ 'site.css': '@font-face{src:url("https://fonts.example.com/f.woff2")}' });
    assert.equal(problems.length, 1);
    assert.match(problems[0], /another origin at runtime/);
  });

  it('reports an external url() in a style attribute', () => {
    const problems = problemsFor({
      'index.html': page(`<div style="background:url('https://img.example.com/b.png')"></div>`),
    });
    assert.equal(problems.length, 1);
    assert.match(problems[0], /another origin at runtime/);
  });

  it('reports an external url() in an inline style element', () => {
    const problems = problemsFor({
      'index.html': page('', '<style>a{background:url(https://img.example.com/b.png)}</style>'),
    });
    assert.equal(problems.length, 1);
  });

  it('reports every external srcset candidate', () => {
    const problems = problemsFor({
      'index.html': page('<img srcset="https://img.example.com/a.png 1x, https://img.example.com/b.png 2x">'),
    });
    assert.equal(problems.length, 2);
  });

  it('reports links written with single quotes or no quotes', () => {
    const problems = problemsFor({
      'index.html': page(`<a href='/supermgmt/missing-one/'>x</a><a href=/supermgmt/missing-two/>y</a>`),
    });
    assert.equal(problems.length, 2);
  });

  it('does not report a canonical link, an external anchor or navigation rels', () => {
    const problems = problemsFor({
      'index.html': page(
        '<a href="https://github.com/autarquico/supermgmt">repo</a>',
        [
          '<link rel="canonical" href="https://autarquico.github.io/supermgmt/">',
          '<link rel="alternate" href="https://example.com/feed.xml">',
        ].join(''),
      ),
    });
    assert.deepEqual(problems, []);
  });

  it('does not read URLs inside a script body', () => {
    const problems = problemsFor({
      'index.html': page(`<script>const tag = '<script src="https://cdn.example.com/a.js"></script>';</script>`),
    });
    assert.deepEqual(problems, []);
  });
});

describe('parseTags', () => {
  it('reads double-quoted, single-quoted and unquoted attributes', () => {
    const [tag] = parseTags(`<a href="/a/" title='t' data-x=y hidden>`);
    assert.equal(tag.name, 'a');
    assert.deepEqual(tag.attributes, { href: '/a/', title: 't', 'data-x': 'y', hidden: '' });
  });

  it('decodes entities in attribute values', () => {
    const [tag] = parseTags('<a href="/a/?x=1&amp;y=2">');
    assert.equal(tag.attributes.href, '/a/?x=1&y=2');
  });
});

describe('cssUrls', () => {
  it('finds quoted, unquoted and @import urls', () => {
    const urls = cssUrls(`a{background:url("a.png")} b{background:url(b.png)} @import 'c.css';`);
    assert.deepEqual(urls, ['a.png', 'b.png', 'c.css']);
  });
});
