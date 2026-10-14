import assert from 'node:assert/strict';
import { mkdirSync, mkdtempSync, readdirSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { test } from 'node:test';
import { parseManifest, routeFor, syncDocs, transformPage } from './sync-docs.mjs';

const existing = new Set(['docs/page.md', 'docs/other.md', 'docs/internal.md', 'SECURITY.md', 'examples', 'docs/adr/0001-x.md']);
const kindOf = (repoPath) => (existing.has(repoPath) ? (repoPath === 'examples' ? 'dir' : 'file') : null);
const publicFiles = new Set(['page.md', 'other.md']);
const transform = (source, base = '/supermgmt/') =>
  transformPage({ file: 'page.md', source, publicFiles, base, kindOf });

test('manifest keeps section and page order', () => {
  const sections = parseManifest('# c\n\n[A]\none.md\n# hidden.md\ntwo.md\n[B]\nthree.md\n');
  assert.deepEqual(sections, [
    { label: 'A', files: ['one.md', 'two.md'] },
    { label: 'B', files: ['three.md'] },
  ]);
});

test('manifest rejects duplicates, nested paths and pages without a section', () => {
  assert.throws(() => parseManifest('[A]\none.md\none.md\n'), /listed twice/);
  assert.throws(() => parseManifest('[A]\nadr/one.md\n'), /flat/);
  assert.throws(() => parseManifest('one.md\n'), /before any \[Section\]/);
});

test('first H1 becomes the title and is removed from the body', () => {
  const page = transform('# Compatibility (`sm`)\n\nIntro.\n');
  assert.equal(page, '---\ntitle: "Compatibility (sm)"\n---\n\nIntro.\n');
});

test('titles with quotes stay valid front matter', () => {
  assert.match(transform('# Say "hi": now\n'), /^---\ntitle: "Say \\"hi\\": now"\n---\n/);
});

test('later H1 headings become H2 and keep their text, so anchors survive', () => {
  const page = transform('# Title\n\n# Second part\n\ntext\n\n# Third\n');
  assert.equal((page.match(/^# /gm) ?? []).length, 0);
  assert.match(page, /^## Second part$/m);
  assert.match(page, /^## Third$/m);
});

test('shell comments inside code fences are not headings', () => {
  const source = '# Title\n\n```sh\n# a comment\nsm x\n```\n\n~~~\n# also code\n~~~\n';
  const page = transform(source);
  assert.match(page, /^# a comment$/m);
  assert.match(page, /^# also code$/m);
});

test('a page without H1 is an error', () => {
  assert.throws(() => transform('Just text\n'), /no top-level/);
});

test('front matter in a source page is an error', () => {
  assert.throws(() => transform('---\na: b\n---\n# T\n'), /front matter/);
});

test('links to public pages become site routes under the base and keep the fragment', () => {
  const page = transform('# T\n\nSee [other](other.md#a-b) and [self](page.md).\n');
  assert.match(page, /\[other\]\(\/supermgmt\/other\/#a-b\)/);
  assert.match(page, /\[self\]\(\/supermgmt\/page\/\)/);
});

test('links to anything else become GitHub URLs, files as blob and folders as tree', () => {
  const page = transform('# T\n\n[a](internal.md) [b](../SECURITY.md#x) [c](../examples) [d](adr/0001-x.md)\n');
  assert.match(page, /\[a\]\(https:\/\/github\.com\/autarquico\/supermgmt\/blob\/main\/docs\/internal\.md\)/);
  assert.match(page, /\[b\]\(https:\/\/github\.com\/autarquico\/supermgmt\/blob\/main\/SECURITY\.md#x\)/);
  assert.match(page, /\[c\]\(https:\/\/github\.com\/autarquico\/supermgmt\/tree\/main\/examples\)/);
  assert.match(page, /\[d\]\(https:\/\/github\.com\/autarquico\/supermgmt\/blob\/main\/docs\/adr\/0001-x\.md\)/);
});

test('same-page anchors and absolute URLs are left alone', () => {
  const source = '# T\n\n[a](#here) [b](https://example.com/x) [c](mailto:a@b.c)\n';
  assert.equal(transform(source), `---\ntitle: "T"\n---\n\n[a](#here) [b](https://example.com/x) [c](mailto:a@b.c)\n`);
});

test('links inside code fences and inline code are not rewritten', () => {
  const page = transform('# T\n\n`[x](other.md)`\n\n```\n[y](other.md)\n```\n');
  assert.equal((page.match(/\]\(other\.md\)/g) ?? []).length, 2);
});

test('reference-style definitions are rewritten', () => {
  assert.match(transform('# T\n\n[ref]: other.md#z\n'), /^\[ref\]: \/supermgmt\/other\/#z$/m);
});

test('a link to a missing file is an error', () => {
  assert.throws(() => transform('# T\n\n[x](nope.md)\n'), /does not exist/);
});

test('the base is applied through one helper', () => {
  assert.equal(routeFor('a', '/'), '/a/');
  assert.match(transform('# T\n\n[o](other.md)\n', '/x/'), /\(\/x\/other\/\)/);
});

function fixtureRepo(manifest, pages) {
  const root = mkdtempSync(path.join(tmpdir(), 'sync-docs-'));
  mkdirSync(path.join(root, 'docs'));
  writeFileSync(path.join(root, 'docs', 'public-pages.txt'), manifest);
  for (const [name, content] of Object.entries(pages)) writeFileSync(path.join(root, 'docs', name), content);
  return root;
}

test('only manifest pages are copied; internal pages never reach the output', () => {
  const root = fixtureRepo('[S]\na.md\n', { 'a.md': '# A\n\n[i](STATUS.md)\n', 'STATUS.md': '# Status\n' });
  const out = path.join(root, 'out');
  mkdirSync(out);
  writeFileSync(path.join(out, 'stale.md'), 'old');
  syncDocs({ root, out });
  assert.deepEqual(readdirSync(out), ['a.md']);
  assert.match(readFileSync(path.join(out, 'a.md'), 'utf8'), /blob\/main\/docs\/STATUS\.md/);
});

test('a listed page that does not exist fails the sync', () => {
  const root = fixtureRepo('[S]\nmissing.md\n', {});
  assert.throws(() => syncDocs({ root, out: path.join(root, 'out') }), /does not exist/);
});
