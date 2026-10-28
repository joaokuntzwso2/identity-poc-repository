import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import vm from 'node:vm';

const code = readFileSync(new URL('../services/identity-bff/src/live-experience-v5.js', import.meta.url), 'utf8');
const server = readFileSync(new URL('../services/identity-bff/src/server.js', import.meta.url), 'utf8');

async function boot(pathname, me = { identitySource:'NO_VERIFIED_IDENTITY', authenticated:false, clients:{}, csrf:'test-csrf' }) {
  const elements = new Map(), calls=[];
  const make = () => ({ value:'', disabled:false, textContent:'', innerHTML:'', children:[], dataset:{},
    append(...nodes){this.children.push(...nodes);}, replaceChildren(){this.children=[];},
    set onclick(fn){this.action=fn;}, get onclick(){return this.action;} });
  const app=make(); app.events={}; app.addEventListener=(name,cb)=>{app.events[name]=cb;};
  const document={
    getElementById(id){ if(id==='root')return app; if(!elements.has(id))elements.set(id,make());return elements.get(id); },
    querySelectorAll(){return [];},
    createElement(){return make();}
  };
  const location={pathname,hash:'',assigned:null,assign(x){this.assigned=x;}};
  const fetch=async (url,opts)=>{
    calls.push({url,method:opts?.method||'GET',opts});
    const data=url==='/api/identity/me'?me:
      url.startsWith('/api/brands/') && url.includes('/profile')?{allowed:true,attributes:{email:'released@example.test'}}:
      url.includes('/cases')?{visibility:'OWNER_ONLY',records:[]}:
      url==='/api/wso2-status'?{statuses:[]}:{status:'BFF_SESSION_DESTROYED'};
    return {status:200,ok:true,json:async()=>data};
  };
  vm.runInNewContext(code, { document,window:{addEventListener(){}},location,history:{replaceState(){}},fetch,console });
  await new Promise(resolve=>setImmediate(resolve));
  return {app,elements,calls,location};
}

test('restored lab has all six guided journeys and four separate client routes', async()=>{
  const x=await boot('/lab');
  assert.match(x.app.innerHTML,/Uma identidade/);
  assert.match(x.app.innerHTML,/Explorar jornadas/);
  for(const p of ['/portal/aurora/web','/portal/aurora/mobile','/portal/brisa/web','/portal/brisa/mobile'])
    assert.ok(x.app.innerHTML.includes(p),p);
  const btn={dataset:{nav:'journeys'}};
  await x.app.events.click({target:{closest:()=>btn}});
  for(const n of ['Uma pessoa. Duas marcas.','Segurança no momento certo.','Dados com controle e propósito.',
    'Cada empresa governa seus acessos.','Delegação sem privilégio excessivo.','Uma nova marca, sem interrupção.'])
    assert.ok(x.app.innerHTML.includes(n));
  assert.deepEqual(x.calls.map(x=>x.url),['/api/identity/me']);
});

test('each brand/channel uses the corresponding real BFF client, no automatic login',async()=>{
  for(const [path,key,route] of [
    ['/portal/aurora/web','aurora-web','/auth/aurora-web/login'],
    ['/portal/aurora/mobile','aurora-app','/auth/aurora-mobile/login'],
    ['/portal/brisa/web','brisa-web','/auth/brisa-web/login'],
    ['/portal/brisa/mobile','brisa-app','/auth/brisa-mobile/login']]) {
    const x=await boot(path);
    assert.match(x.app.innerHTML,/Ainda não autenticado/);
    assert.match(x.app.innerHTML, /id="site-profile"[^>]*disabled/);
    assert.match(x.app.innerHTML, /id="v5-case-create"[^>]*disabled/);
    x.elements.get('site-login').action();
    assert.ok(x.location.assigned.startsWith(route+'?returnTo='));
    assert.ok(x.location.assigned.includes(encodeURIComponent(path)));
    assert.equal(x.calls.length,1,'only live identity/me queried');
  }
});

test('real session scopes enable only permitted actions, UserInfo uses matching client',async()=>{
  const me={identitySource:'WSO2_ID_TOKEN_AND_LIVE_ACCESS_TOKEN',authenticated:true,
    csrf:'csrf-only-from-bff',clients:{'brisa-app':{authenticated:true,issuer:'https://example.test/t/brisa',
    subjectFingerprint:'verified-fingerprint',permissions:['ciam:profile:read','ciam:cases:read'],
    rolesFromVerifiedIdToken:[],claimsFromVerifiedIdToken:{name:'WSO2 Released Name'}}}};
  const x=await boot('/portal/brisa/mobile',me);
  assert.equal(x.elements.get('site-profile').disabled,false);
  assert.equal(x.elements.get('v5-case-create').disabled,true);
  assert.equal(x.elements.get('v5-case-list-btn').disabled,false);
  assert.equal(x.elements.get('v5-case-approve').disabled,true);
  await x.elements.get('site-profile').action();
  assert.ok(x.calls.some(c=>c.url==='/api/brands/brisa/profile?client=brisa-app'));
  assert.ok(!x.calls.some(c=>c.url.includes('aurora')));
});

test('source does not revive synthetic authority or cross-tenant callback return URLs',()=>{
  for (const dangerous of ['/api/experience','/api/retail','personas.json','localStorage','sessionStorage','mockAccessToken'])
    assert.ok(!code.includes(dangerous),dangerous);
  assert.match(server,/CIAM_V5_RETURNTO/);
  assert.match(server,/asked === `\/portal\/\$\{brand\}\/mobile` && key === `\$\{brand\}-app`/);
  assert.match(server,/if \(process\.env\.IDENTITY_MODE !== 'live-wso2'\)/);
  assert.match(server,/requireAuthorityForClient/);
});
