import AxeBuilder from '@axe-core/playwright';
import { expect, test, type Page } from '@playwright/test';

const PAGES = [
  { name: 'landing', path: '/supermgmt/' },
  { name: 'getting-started', path: '/supermgmt/getting-started/' },
  { name: 'cli', path: '/supermgmt/cli/' },
  { name: 'compatibility', path: '/supermgmt/compatibility/' },
];
const THEMES = ['light', 'dark'] as const;
const VIEWPORTS = [
  { name: '360px', width: 360, height: 780 },
  { name: 'desktop', width: 1280, height: 800 },
];
const WCAG_TAGS = ['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa', 'wcag22aa'];

async function open(page: Page, path: string, theme: (typeof THEMES)[number], width: number, height: number) {
  await page.setViewportSize({ width, height });
  await page.emulateMedia({ colorScheme: theme });
  await page.addInitScript((value) => localStorage.setItem('starlight-theme', value), theme);
  await page.goto(path, { waitUntil: 'networkidle' });
}

for (const { name, path } of PAGES) {
  for (const theme of THEMES) {
    for (const viewport of VIEWPORTS) {
      test.describe(`${name} · ${theme} · ${viewport.name}`, () => {
        test.beforeEach(({ page }) => open(page, path, theme, viewport.width, viewport.height));

        test('there is no horizontal scroll', async ({ page }) => {
          const { scrollWidth, clientWidth } = await page.evaluate(() => ({
            scrollWidth: document.documentElement.scrollWidth,
            clientWidth: document.documentElement.clientWidth,
          }));
          expect(scrollWidth).toBeLessThanOrEqual(clientWidth);
        });

        test('contrast and structure meet WCAG AA', async ({ page }) => {
          const { violations } = await new AxeBuilder({ page }).withTags(WCAG_TAGS).analyze();
          expect(
            violations.map(({ id, nodes }) => `${id}: ${nodes.map((n) => n.target.join(' ')).join(' | ')}`),
          ).toEqual([]);
        });

        test('wide content scrolls inside its own region', async ({ page }) => {
          const stranded = await page.evaluate(() => {
            const viewportWidth = document.documentElement.clientWidth;
            const hasScrollableAncestor = (el: Element) => {
              for (let a = el.parentElement; a && a !== document.body; a = a.parentElement) {
                if (getComputedStyle(a).overflowX !== 'visible' && a.scrollWidth > a.clientWidth) return true;
              }
              return false;
            };
            return [...document.querySelectorAll('main pre, main table, main img, main svg')]
              .filter((el) => el.getBoundingClientRect().right > viewportWidth + 1 && !hasScrollableAncestor(el))
              .map((el) => el.tagName.toLowerCase());
          });
          expect(stranded).toEqual([]);
        });

        test('focus is visible on every keyboard stop', async ({ page }) => {
          const invisible: string[] = [];
          for (let i = 0; i < 25; i += 1) {
            await page.keyboard.press('Tab');
            const state = await page.evaluate(() => {
              const el = document.activeElement;
              if (!el || el === document.body) return null;
              const s = getComputedStyle(el);
              const outlined = s.outlineStyle !== 'none' && parseFloat(s.outlineWidth) > 0;
              const shadowed = s.boxShadow !== 'none';
              const text = (el.textContent ?? '').trim().slice(0, 30);
              return { label: `${el.tagName.toLowerCase()} "${text}"`, visible: outlined || shadowed };
            });
            if (state && !state.visible) invisible.push(state.label);
          }
          expect(invisible).toEqual([]);
        });
      });
    }
  }
}

test('no page loads a resource from another origin', async ({ page, baseURL }) => {
  const foreign: string[] = [];
  page.on('request', (request) => {
    const url = request.url();
    if (!url.startsWith('data:') && !url.startsWith('blob:') && !url.startsWith(baseURL!)) foreign.push(url);
  });
  for (const { path } of PAGES) await page.goto(path, { waitUntil: 'networkidle' });
  expect(foreign).toEqual([]);
});

test('search opens from the keyboard and finds a docs page', async ({ page }) => {
  await open(page, '/supermgmt/getting-started/', 'dark', 1280, 800);
  await page.keyboard.press('Control+k');
  const dialog = page.locator('dialog[open]');
  await expect(dialog).toBeVisible();
  // Pagefind loads its index on first use; on a cold CI runner that can take a few seconds.
  const input = dialog.getByRole('textbox', { name: 'Search' });
  await expect(input).toBeFocused({ timeout: 15_000 });
  await input.pressSequentially('approvals');
  await expect(dialog.locator('.pagefind-ui__result-link').first()).toBeVisible({ timeout: 15_000 });
  await page.keyboard.press('Escape');
  await expect(dialog).toBeHidden();
});

test('search is reachable by keyboard at 360 px', async ({ page }) => {
  await open(page, '/supermgmt/getting-started/', 'light', 360, 780);
  await page.locator('button[data-open-modal]').first().focus();
  await page.keyboard.press('Enter');
  await expect(page.locator('dialog[open]')).toBeVisible();
});
