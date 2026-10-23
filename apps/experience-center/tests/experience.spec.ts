import {test,expect} from '@playwright/test';

test('premium dashboard is rendered from application source',async({page})=>{
 await page.goto('/');
 await expect(page.getByText('Uma identidade.')).toBeVisible();
 await expect(page.getByText('Visão geral do ambiente')).toBeVisible();
 await page.getByRole('button',{name:'Experiências das marcas'}).click();
 await expect(page.getByRole('heading',{name:'Duas marcas. Uma experiência contínua.'})).toBeVisible();
 await expect(page.getByText('Aurora · Web')).toHaveCount(0); // Only inspector has this label
 await expect(page.locator('a[href="/auth/aurora-web/login"]')).toBeVisible();
 await expect(page.locator('a[href="/auth/brisa-app/login"]')).toBeVisible();
});

test('RFP evidence dashboard never fabricates PASS status',async({page})=>{
 await page.goto('/');
 await page.getByRole('button',{name:'Evidências do RFP'}).click();
 await expect(page.getByText('Evidências verificáveis')).toBeVisible();
 await expect(page.locator('.scenario-row')).toHaveCount(13);
 await expect(page.getByText('NOT_VERIFIED', {exact:true})).toHaveCount(0); // Implementation statuses have readable labels
 await expect(page.locator('.scenario-row').first()).toContainText('Identificador pairwise por marca');
});

test('live signed four-client identity gate requires real pre-authenticated browser state',async({page})=>{
 test.skip(process.env.RUN_LIVE_IDENTITY_TESTS!=='yes','No signed WSO2 test fixture or pre-authorized sessions available');
 await page.goto('/');
 const s=await page.request.get('/api/subjects/compare');
 const result=await s.json();
 expect(result.status).toBe('IDENTIFIER_PREDICATE_MET');
 expect(result.predicate).toBe(true);
 expect(result.canonicalPerson).toBe('NOT_VERIFIED');
 // This verifies only the mathematical predicate. Canonical person remains an independent buyer acceptance gate.
});
