import {test,expect} from '@playwright/test';

test('guided demo starts in presenter preview mode',async({page})=>{
 await page.goto('/');
 await expect(page.getByText('Uma identidade.')).toBeVisible();
 await page.getByRole('button',{name:/Explorar jornadas/}).click();
 await expect(page.getByText('Jornadas que conectam negócio e arquitetura')).toBeVisible();
 await expect(page.getByText('Story Preview')).toBeVisible();
 await page.getByRole('button',{name:'Técnico'}).click();
 await expect(page.getByText('Controles arquiteturais')).toBeVisible();
});
test('Aurora and Brisa look and navigate differently',async({page})=>{
 await page.goto('/');
 await page.getByRole('button',{name:/Aurora Store/}).click();
 await expect(page.getByText('Tecnologia que acompanha você.')).toBeVisible();
 await page.getByRole('button',{name:/Brisa Living/}).click();
 await expect(page.getByText('Seu lugar de sentir-se em casa.')).toBeVisible();
});
test('mobile preview prominently states it is a browser simulation',async({page})=>{
 await page.goto('/');await page.getByRole('button',{name:/Aurora Store/}).click();
 await page.getByRole('button',{name:/Mobile/}).click();
 await expect(page.getByText(/Simulação mobile no navegador/)).toBeVisible();
});
