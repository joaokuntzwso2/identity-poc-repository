import { test, expect } from '@playwright/test';
import { startIsolatedLiveBff } from '../../../services/identity-bff/test/helpers/live-test-harness.js';

// Isolated BFF with a disposable, test-only OIDC manifest: never connects to live WSO2.
let base: string;
let stop: (() => Promise<void>) | undefined;
test.beforeAll(async () => {
  const server = await startIsolatedLiveBff();
  base = server.base;
  stop = server.close;
});
test.afterAll(async () => { await stop?.(); });

for (const brand of ['aurora', 'brisa'] as const) {
  for (const width of [320, 375, 768, 1280]) {
    test(`${brand} MOBILE at ${width}px is responsive and keeps its independent WSO2 client`, async ({ page }) => {
      await page.setViewportSize({ width, height: 820 });
      await page.goto(`${base}/portal/${brand}/mobile`);
      const frame = page.getByTestId('live-retail-device');
      const screen = page.getByTestId('live-retail-screen');
      await expect(page.getByTestId('live-retail-stage')).toBeVisible();
      await expect(frame).toBeVisible();
      await expect(page.locator('.v5-mobile-site')).toHaveClass(new RegExp(`retail-${brand}`));
      await expect(page.locator('.v5-header-login')).toHaveAttribute('href',
        new RegExp(`^/auth/${brand}-mobile/login[?]`));
      await expect(page.locator('#site-identity')).toContainText('Ainda não autenticado');
      await expect(page.locator('#v5-case-create')).toBeDisabled();
      await expect(page.locator('#v5-case-list-btn')).toBeDisabled();
      await expect(page.locator('#v5-case-title')).toBeVisible();
      const size = await page.evaluate(() => ({ document: document.documentElement.scrollWidth, viewport: innerWidth }));
      expect(size.document).toBeLessThanOrEqual(size.viewport + 1);
      const screenSize = await screen.evaluate(el => ({ scroll: el.scrollWidth, client: el.clientWidth }));
      expect(screenSize.scroll).toBeLessThanOrEqual(screenSize.client + 1);
      if (width <= 700) {
        await expect(frame).toHaveCSS('border-left-width', '0px');
        await expect(page.locator('.v5-retail-stage-context')).toBeHidden();
      } else {
        await expect(frame).toHaveCSS('border-left-width', '7px');
        await expect(page.getByRole('heading', { name: `${brand === 'aurora' ? 'Aurora' : 'Brisa'} Mobile` })).toBeVisible();
      }
    });
  }
  for (const width of [375, 1280]) {
    test(`${brand} WEB at ${width}px keeps original unframed storefront and web OIDC client`, async ({ page }) => {
      await page.setViewportSize({ width, height: 820 });
      await page.goto(`${base}/portal/${brand}/web`);
      await expect(page.getByTestId('live-retail-stage')).toHaveCount(0);
      await expect(page.getByTestId('live-retail-device')).toHaveCount(0);
      await expect(page.locator('#root > .retail-site')).toBeVisible();
      await expect(page.locator('.retail-site')).not.toHaveClass(/v5-mobile-site/);
      await expect(page.locator('.v5-header-login')).toHaveAttribute('href',
        new RegExp(`^/auth/${brand}-web/login[?]`));
      await expect(page.locator('#site-identity')).toContainText('Ainda não autenticado');
      await expect(page.locator('#v5-case-create')).toBeDisabled();
      const size = await page.evaluate(() => ({ document: document.documentElement.scrollWidth, viewport: innerWidth }));
      expect(size.document).toBeLessThanOrEqual(size.viewport + 1);
    });
  }
}
test('Experience Center laboratory remains unframed', async ({ page }) => {
  await page.goto(`${base}/lab`);
  await expect(page.getByTestId('live-retail-stage')).toHaveCount(0);
  await expect(page.locator('.app-shell')).toHaveCount(1);
});
