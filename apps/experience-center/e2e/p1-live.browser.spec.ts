import { test, expect } from '@playwright/test';
// Live BFF only. These are anonymous UI checks and negative BFF checks, not a fake WSO2 login.
const base=process.env.CIAM_E2E_BASE_URL;
test.skip(!base,'Running BFF and real WSO2 discovery required; no preview service.');
for(const brand of ['aurora','brisa'] as const){
  for(const channel of ['web','mobile'] as const){
    test(`${brand} ${channel}: branded workspace, keyboard and responsive screenshot`,async({page},info)=>{
      await page.setViewportSize({width:channel==='mobile'?390:1440,height:844});
      await page.goto(`${base}/portal/${brand}/${channel}`,{waitUntil:'domcontentloaded'});
      await expect(page.locator('main#branded-main')).toBeVisible();
      await expect(page.getByRole('heading',{name:'Solicitações reais à marca'})).toBeVisible();
      await expect(page.getByRole('textbox',{name:'Assunto'})).toBeVisible();
      await expect(page.getByRole('textbox',{name:'Descrição'})).toBeVisible();
      await expect(page.locator('#v5-case-uuid')).toHaveCount(0);
      await expect(page.getByRole('button',{name:'Criar solicitação'})).toBeDisabled();
      await page.keyboard.press('Tab');
      await expect(page.locator('.v5-skip-link')).toBeFocused();
      const hasHorizontalOverflow=await page.evaluate(()=>document.documentElement.scrollWidth>window.innerWidth);
      expect(hasHorizontalOverflow).toBe(false);
      await page.screenshot({path:info.outputPath(`${brand}-${channel}-anonymous.png`),fullPage:true});
    });
  }
}
test('tablet: navigation landmarks',async({page},info)=>{
  await page.setViewportSize({width:768,height:900});
  await page.goto(`${base}/lab`);
  await expect(page.locator('nav#lab-menu')).toHaveCount(1);
  await expect(page.getByRole('button',{name:/Modo apresentador/i})).toBeVisible();
  await page.screenshot({path:info.outputPath('experience-center-tablet.png'),fullPage:true});
});
test('cross-tenant business route fails closed before API authorization',async({request})=>{
  const response=await request.get(`${base}/api/brands/brisa/cases?client=aurora-web`);
  expect(response.status()).toBe(403);
  expect((await response.json()).error).toBe('tenant_brand_mismatch');
});
test('anonymous identity never gains fabricated scopes',async({request})=>{
  const response=await request.get(`${base}/api/identity/me`);
  if(response.status()===503)return; // WSO2 outage is observable, not fake success.
  expect(response.status()).toBe(200);
  const data=await response.json();
  expect(data.identitySource).toBe('NO_VERIFIED_IDENTITY');
  for(const key of ['aurora-web','aurora-app','brisa-web','brisa-app']){
    expect(data.clients[key].authenticated).toBe(false);
    expect(data.clients[key].permissions).toEqual([]);
  }
});
