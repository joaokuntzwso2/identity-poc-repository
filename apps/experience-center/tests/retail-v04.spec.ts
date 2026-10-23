import {test,expect} from '@playwright/test';

test('Aurora has standalone functional store and customer account',async({page})=>{
 await page.goto('/aurora.html?persona=customer-ana');
 await expect(page.getByRole('heading',{name:/O futuro cabe/})).toBeVisible();
 await page.getByRole('button',{name:'Novidades'}).click();
 await expect(page.getByRole('heading',{name:'Tecnologia para cada momento'})).toBeVisible();
 await page.getByRole('button',{name:'Ver Fone Studio Pro'}).click();
 await expect(page.getByRole('heading',{name:'Fone Studio Pro'})).toBeVisible();
 await page.getByRole('button',{name:/Adicionar ao carrinho/}).click();
 await page.getByRole('button',{name:/Carrinho com 1 itens/}).click();
 await expect(page.getByText('R$ 799,00').first()).toBeVisible();
});
test('Brisa is visually distinct and has full customer privacy navigation',async({page})=>{
 await page.goto('/brisa.html?persona=customer-ana');
 await expect(page.getByRole('heading',{name:/Viver bem é/})).toBeVisible();
 await page.getByRole('button',{name:'Minha conta'}).click();
 await page.getByRole('button',{name:/Privacidade e consentimento/}).click();
 await expect(page.getByRole('heading',{name:'Você escolhe o que compartilhar.'})).toBeVisible();
 await expect(page.getByText('Inspiração personalizada')).toBeVisible();
});
test('Customer can alter synthetic preferences and manage preview security',async({page})=>{
 await page.goto('/aurora.html?persona=customer-ana');
 await page.getByRole('button',{name:'Minha conta'}).click();
 await page.getByRole('button',{name:/Notificações e preferências/}).click();
 await page.getByRole('checkbox',{name:/Ofertas por e-mail/}).check();
 await page.getByRole('button',{name:/Salvar preferências/}).click();
 await expect(page.getByRole('status')).toContainText('Preferências da marca atualizadas');
 await page.getByRole('button',{name:/Senhas e segurança/}).click();
 await page.getByRole('button',{name:'Simular cadastro'}).first().click();
 await expect(page.getByText('Configuração ilustrativa ativada')).toBeVisible();
});
test('Mobile viewport has fixed shop navigation and demo disclosure',async({page})=>{
 await page.setViewportSize({width:375,height:812});
 await page.goto('/brisa.html?persona=customer-ana');
 await expect(page.getByText('AMBIENTE FICTÍCIO')).toBeVisible();
 await expect(page.getByRole('navigation',{name:'Navegação rápida'})).toBeVisible();
 await page.getByRole('navigation',{name:'Navegação rápida'}).getByRole('button',{name:'Explorar'}).click();
 await expect(page.getByRole('heading',{name:'Objetos com histórias para contar'})).toBeVisible();
});
