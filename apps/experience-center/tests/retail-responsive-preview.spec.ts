import { test, expect } from '@playwright/test';

// These pages are informational access previews; protected workflows remain on the BFF.
for (const brand of ['aurora', 'brisa'] as const) {
  for (const width of [320, 375, 768, 1280]) {
    test(`${brand} web preview at ${width}px has no horizontal overflow and keeps BFF link`, async ({ page }) => {
      await page.setViewportSize({ width, height: 820 });
      await page.goto(`/${brand}.html`);
      await expect(page.getByTestId('retail-device-frame')).toBeVisible();
      await expect(page.getByRole('heading', { name: `${brand === 'aurora' ? 'Aurora' : 'Brisa'} · Web` })).toBeVisible();
      await expect(page.getByRole('link', { name: /Abrir portal real/ })).toHaveAttribute('href', new RegExp(`/portal/${brand}/web$`));
      const dimensions = await page.evaluate(() => ({ page: document.documentElement.scrollWidth, viewport: innerWidth }));
      expect(dimensions.page).toBeLessThanOrEqual(dimensions.viewport + 1);
      if (width <= 375) {
        const borderWidth = await page.getByTestId('retail-device-frame').evaluate(el => getComputedStyle(el).borderLeftWidth);
        expect(borderWidth).toBe('0px');
      }
    });
  }
}
