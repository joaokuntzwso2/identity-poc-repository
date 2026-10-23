import {test} from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync,existsSync} from 'node:fs';
const root=new URL('../../',import.meta.url);
const load=path=>readFileSync(new URL(path,root),'utf8');
test('authorization and other operations HTML pages are independent frontend entrypoints',()=>{
 for(const name of ['authorization','b2b','onboarding','evidence-lab']){
  const url=new URL(`apps/experience-center/${name}.html`,root);
  assert(existsSync(url),`Missing ${name}.html`);
  assert.match(readFileSync(url,'utf8'),new RegExp(`data-operations-page="${name}"`));
 }
});
test('dev config does not use old 4100 catch-all proxy',()=>{
 const vite=load('apps/experience-center/identity.dev.vite.config.ts');
 assert.doesNotMatch(vite,/target\s*:\s*['"]http:\/\/127\.0\.0\.1:4100/);
 assert.match(vite,/['"]\/api['"]\s*:\s*\{/);
 assert.match(vite,/4317/);
 const runner=load('experience.sh');
 assert.match(runner,/vite --config identity\.dev\.vite\.config\.ts/);
});
test('backend actually routes operations requests to fixture policy domain',()=>{
 const s=load('services/experience-api/server.mjs');
 assert.match(s,/createOperationsRoutes\(store\.db\)/);
 assert.match(s,/await operationsRoute\(\{req,res,path,send,body\}\)/);
});
test('TypeScript build regressions addressed without disabling type-checking',()=>{
 assert.match(load('apps/experience-center/src/vite-env.d.ts'),/vite\/client/);
 const center=load('apps/experience-center/src/main.tsx');
 assert.match(center,/function\s+resolveSidebarTitle\s*\(/);
 assert.match(center,/resolveSidebarTitle\s*\(\s*sidebar\s*,\s*area\s*\)/);
 assert.doesNotMatch(center,/sidebar\s*\.\s*flatMap\s*\(/);
 assert.match(load('apps/experience-center/src/operations/OperationsLab.tsx'),/children\?:React\.ReactNode/);
 const runner=load('experience.sh');
 assert.match(runner,/npm --prefix apps\/experience-center run build/);
 assert.match(runner,/operations\.vite\.config\.ts/);
});
