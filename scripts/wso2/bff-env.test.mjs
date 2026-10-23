import test from 'node:test';import assert from 'node:assert/strict';
import {renderBffEnvironment} from './bff-env.mjs';import {config} from './domain.mjs';
const c=config();const credentials={clients:Object.fromEntries(c.brands.flatMap(b=>b.clients.map(a=>[a.key,{clientId:'cid-'+a.key,clientSecret:'secret-'+a.key}])))};
const env={DEMO_BFF_BASE_URL:'http://127.0.0.1:4000',DEMO_AURORA_SECTOR_BASE_URL:'https://aurora-sectors.example.invalid',DEMO_BRISA_SECTOR_BASE_URL:'https://brisa-sectors.example.invalid',WSO2_BASE_URL:'https://localhost:9443',WSO2_OIDC_ISSUER:'https://localhost:9443/oauth2/token'};
test('private BFF bridge maps exactly the four existing /auth/{brand}-{web,app}/callback routes',()=>{
 const data=renderBffEnvironment(c,credentials,env);
 for(const [k,id] of [['AURORA_WEB','AURORA_WEB'],['AURORA_APP','AURORA_MOBILE'],['BRISA_WEB','BRISA_WEB'],['BRISA_APP','BRISA_MOBILE']])assert.match(data,new RegExp(`OIDC_${k}_CLIENT_ID='cid-${id}'`));
 assert.match(data,/PUBLIC_ORIGIN='http:\/\/127\.0\.0\.1:4000'/);
 assert.match(data,/OIDC_ISSUER='https:\/\/localhost:9443\/oauth2\/token'/);
 assert.doesNotMatch(data,/\/api\/auth\/callback/);
});
test('bridge fails closed for missing secrets or wrong issuer/security configuration',()=>{
 assert.throws(()=>renderBffEnvironment(c,{clients:{}},env),/MISSING_REAL_CLIENT_SECRET/);
 assert.throws(()=>renderBffEnvironment(c,credentials,{...env,WSO2_OIDC_ISSUER:'https://attacker.invalid/oauth2/token'}),/OIDC_ISSUER_SECURITY_MISMATCH/);
 assert.throws(()=>renderBffEnvironment(c,credentials,{...env,DEMO_BFF_BASE_URL:'http://public.example'}),/INVALID_BFF_PUBLIC_ORIGIN/);
});
