import { readFileSync } from 'node:fs';
import { defineConfig } from 'astro/config';
import starlight from '@astrojs/starlight';
import { BASE, SITE, parseManifest, slugOf } from './scripts/sync-docs.mjs';

const manifest = parseManifest(readFileSync(new URL('../docs/public-pages.txt', import.meta.url), 'utf8'));

export default defineConfig({
  site: SITE,
  base: BASE,
  trailingSlash: 'always',
  integrations: [
    starlight({
      title: 'SuperMgmt',
      social: [{ icon: 'github', label: 'GitHub', href: 'https://github.com/autarquico/supermgmt' }],
      sidebar: manifest.map(({ label, files }) => ({
        label,
        items: files.map((file) => ({ slug: slugOf(file) })),
      })),
    }),
  ],
});
