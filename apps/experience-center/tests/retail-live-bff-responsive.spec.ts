import { test, expect } from '@playwright/test';
import { startIsolatedLiveBff } from '../../../services/identity-bff/test/helpers/live-test-harness.js';

// Isolated BFF with test-only OIDC manifest. Does not log in or issue WSO2 writes.
let base: string;
let closeBff: (() => Promise<void>) | undefined;
test.beforeAll(async () => {
  const started = await startIsolatedLiveBff();
  base = started.base;
  closeBff = started.close;
});
test.afterAll(async () => { await closeBff?.(); });

for (const brand of ['aurora','brisa'] as const) {
  for (const width of [320,375,768,1280]) {
    test(`${brand} live web at ${width}px retains login, readable layout and no page overflow`, async ({page}) => {
      await page.setViewportSize({width,height:820});
      await page.goto(`${base}/portal/${brand}/web`);
      const frame=page.getByTestId('live-retail-device');
      const screen=page.getByTestId('live-retail-screen');
      await expect(frame).toBeVisible();
      await expect(page.locator('.retail-site')).toHaveClass(new RegExp(`retail-${brand}`));
      // The external desktop title is intentionally hidden on real phones.
      // The storefront wordmark and its own hero heading must stay visible.
      const outsideTitle = page.locator('.v5-retail-stage-context h1');
      if (width <= 700) {
        await expect(page.locator('.v5-retail-stage-context')).toBeHidden();
        await expect(page.locator('.rt-wordmark')).toBeVisible();
        await expect(page.locator('.rt-wordmark')).toContainText(brand === 'aurora' ? 'AURORA' : 'brisa.');
        await expect(page.locator('#branded-main h1')).toBeVisible();
      } else {
        await expect(page.locator('.v5-retail-stage-context')).toBeVisible();
        await expect(outsideTitle).toHaveText(brand === 'aurora' ? 'Aurora Web' : 'Brisa Web');
      }
      await expect(page.locator('.v5-header-login')).toHaveAttribute('href',new RegExp(`^/auth/${brand}-web/login[?]`));
      await expect(page.locator('.v5-identity-strip #site-identity')).toContainText('Ainda não autenticado');
      await expect(page.locator('#v5-case-create')).toBeDisabled();
      await expect(page.locator('#v5-case-list-btn')).toBeDisabled();
      const sizes=await page.evaluate(() => ({doc:document.documentElement.scrollWidth, viewport:innerWidth}));
      expect(sizes.doc).toBeLessThanOrEqual(sizes.viewport+1);
      const screenSizes=await screen.evaluate(el=>({scroll:el.scrollWidth,client:el.clientWidth}));
      expect(screenSizes.scroll).toBeLessThanOrEqual(screenSizes.client+1);
      if(width<=700) { await expect(frame).toHaveCSS('border-left-width','0px'); }
      else { await expect(frame).toHaveCSS('border-left-width','7px'); }
      await expect(page.locator('#v5-case-title')).toBeVisible();
    });
  }
}
for(const brand of ['aurora','brisa'] as const) {
  test(`${brand} live mobile channel remains unframed and independently authenticated`,async ({page})=>{
    await page.setViewportSize({width:375,height:820});
    await page.goto(`${base}/portal/${brand}/mobile`);
    await expect(page.getByTestId('live-retail-stage')).toHaveCount(0);
    await expect(page.locator('.v5-mobile-site')).toBeVisible();
    await expect(page.locator('.v5-header-login')).toHaveAttribute('href',new RegExp(`^/auth/${brand}-mobile/login[?]`));
  });
}
