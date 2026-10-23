import {test,expect} from '@playwright/test';

test('Aurora mobile is independently navigable inside the simulated device',async({page})=>{
 await page.goto('/aurora-mobile.html?persona=customer-ana');
 await expect(page.getByTestId('device-frame')).toBeVisible();
 await expect(page.getByRole('navigation',{name:'Navegação do Aurora Mobile'})).toBeVisible();
 await expect(page.getByText('PREVIEW SEM WSO2')).toBeVisible();
 await page.getByRole('button',{name:'Conhecer Studio Pro'}).click();
 await expect(page.getByRole('heading',{name:'Fone Studio Pro'})).toBeVisible();
 await page.getByRole('button',{name:/Adicionar à sacola/}).click();
 await page.getByRole('navigation',{name:'Navegação do Aurora Mobile'}).getByRole('button',{name:/Sacola/}).click();
 await expect(page.getByRole('heading',{name:/Minha sacola/})).toBeVisible();
 await page.getByRole('button',{name:/Continuar para aprovação/}).click();
 await expect(page.getByRole('heading',{name:'Você reconhece esta compra?'})).toBeVisible();
 await page.getByRole('checkbox',{name:/Entendo que esta confirmação/}).check();
 await page.getByRole('button',{name:/Aprovar no preview/}).click();
 await expect(page.getByRole('heading',{name:'Meus pedidos.'})).toBeVisible();
});

test('Brisa mobile is independent, its tabs and account preferences are functional',async({page})=>{
 await page.goto('/brisa-mobile.html?persona=customer-ana');
 await expect(page.getByRole('navigation',{name:'Navegação do Brisa Mobile'})).toBeVisible();
 await expect(page.getByRole('heading',{name:/Olá, Ana./})).toBeVisible();
 await page.getByRole('navigation',{name:'Navegação do Brisa Mobile'}).getByRole('button',{name:/Meu espaço/}).click();
 await page.getByRole('button',{name:/Notificações e preferências/}).click();
 await expect(page.getByRole('heading',{name:'Do seu jeito.'})).toBeVisible();
 await page.getByRole('checkbox',{name:/Mensagens por SMS/}).check();
 await page.getByRole('button',{name:'Salvar preferências'}).click();
 await expect(page.getByRole('status')).toContainText('Preferências da marca atualizadas.');
 await page.reload();
 await page.getByRole('navigation',{name:'Navegação do Brisa Mobile'}).getByRole('button',{name:/Meu espaço/}).click();
 await page.getByRole('button',{name:/Notificações e preferências/}).click();
 await expect(page.getByRole('checkbox',{name:/Mensagens por SMS/})).toBeChecked();
});

test('Mobile laboratory can switch simulated phone models and lock screen',async({page})=>{
 await page.goto('/aurora-mobile.html');
 await page.getByRole('button',{name:'Estilo Android'}).click();
 await expect(page.getByTestId('device-frame')).toHaveClass(/lab-device-pixel/);
 await page.getByRole('button',{name:'Bloquear tela'}).click();
 await expect(page.getByRole('button',{name:'Desbloquear simulação'})).toBeVisible();
 await page.getByRole('button',{name:'Desbloquear simulação'}).click();
 await expect(page.getByRole('navigation',{name:'Navegação do Aurora Mobile'})).toBeVisible();
});
