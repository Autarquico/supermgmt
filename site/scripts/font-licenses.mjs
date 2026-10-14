// Copies the OFL-1.1 licence of each self-hosted font into the built site, next to the fonts it covers.
import { copyFileSync, mkdirSync } from 'node:fs';
import { join } from 'node:path';

const fonts = ['@fontsource-variable/geist', '@fontsource-variable/geist-mono', '@fontsource/instrument-serif'];
const out = join('dist', 'licenses', 'fonts');

mkdirSync(out, { recursive: true });
for (const font of fonts) {
  copyFileSync(join('node_modules', font, 'LICENSE'), join(out, `${font.replace(/^@fontsource(-variable)?\//, '')}.txt`));
}
