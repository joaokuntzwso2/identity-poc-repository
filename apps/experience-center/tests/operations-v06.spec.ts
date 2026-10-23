import {test,expect} from '@playwright/test';
// Requires ./experience.sh dev in another terminal. All records are synthetic.
test('B2B portal has working organization actions and safe labeling',async({page})=>{
 await page.goto('http://127.0.0.1:5173/b2b.html');
 await expect(page.getByRole('heading',{name:/Organizações que gerenciam/})).toBeVisible();
 await expect(page.getByText('Laboratório sintético')).toBeVisible();
 await expect(page.getByRole('tab',{name:'Representantes'})).toBeVisible();
 await expect(page.getByRole('button',{name:/Aplicar papel de preview/})).toBeVisible();
});
test('onboarding validates but never provisions',async({page})=>{
 await page.goto('http://127.0.0.1:5173/onboarding.html');
 await expect(page.getByText(/Nenhum tenant real é criado/)).toBeVisible();
 await page.getByRole('button',{name:/Continuar/}).click();
 await page.getByRole('button',{name:/Validar configuração/}).click();
 await expect(page.getByText(/Regras locais de pré-validação aprovadas/)).toBeVisible();
 await page.getByRole('button',{name:/Gerar plano revisável/}).click();
 await expect(page.getByText(/NÃO EXECUTADO/)).toBeVisible();
});
test('authorization denies privilege escalation and stores evidence',async({page})=>{
 await page.goto('http://127.0.0.1:5173/authorization.html');
 await expect(page.getByRole('heading',{name:/Acesso é uma decisão/})).toBeVisible();
 // Client Credentials fixture only has catalog.read, so a user order is rejected.
 await page.getByLabel('Recurso protegido').selectOption('orders.read');
 await page.getByRole('button',{name:/Avaliar política de recurso/}).click();
 await expect(page.getByText(/PREVIEW · NEGADO/)).toBeVisible();
 await page.goto('http://127.0.0.1:5173/evidence-lab.html');
 await expect(page.getByText('cc-resource').first()).toBeVisible();
 await expect(page.getByText('Não verificado').first()).toBeVisible();
});
