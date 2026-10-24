import test from 'node:test';
import assert from 'node:assert/strict';
import {mkdtempSync,mkdirSync,writeFileSync,existsSync,rmSync,copyFileSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join,resolve} from 'node:path';
import {pathToFileURL} from 'node:url';

const code=resolve(import.meta.dirname,'../scripts/wso2/bootstrap-tenant-control-plane.mjs');
function fixture(){
  const dir=mkdtempSync(join(tmpdir(),'wso2-sector-preflight-'));
  const home=join(dir,'scripts/wso2');mkdirSync(home,{recursive:true});
  copyFileSync(code,join(home,'bootstrap-tenant-control-plane.mjs'));
  writeFileSync(join(home,'tenant-control-plane.mjs'),`
    export const assertLab=env=>({base:'https://localhost:9443',domains:{aurora:'aurora.identity.test',brisa:'brisa.identity.test'}});
    export const readPrivate=(p,defaultValue)=>defaultValue;
    export const adminPreflight=async()=>{};
    export const seedManagement=async()=>{throw Error('UNSAFE_REMOTE_WRITE')};
    export const verifyManagement=async()=>({});
  `);
  writeFileSync(join(home,'tenant-brand-clients.mjs'),`
    export const assertPlan=(plan,domains,urls)=>{
       if(plan.apps.length!==4||!urls.aurora||!urls.brisa)throw Error('INVALID_SECTOR_INPUTS');
       return plan.apps;
    };
    export const provisionBrandClients=async()=>{throw Error('UNSAFE_REMOTE_WRITE')};
    export const exportBffContracts=()=>{};
  `);
  writeFileSync(join(home,'domain.mjs'),`
    export const config=()=>({});
    export const deploymentPlan=(c,env)=>({apps:['aurora','brisa'].flatMap(b=>['web','mobile'].map(x=>({brand:b,key:b+'-'+x,callback:'https://'+b+'.example.test/'+x}))) });
  `);
  writeFileSync(join(home,'sector.mjs'),`
    export const sectorUris=env=>{
      if(!env.DEMO_AURORA_SECTOR_BASE_URL)throw Error('DEMO_AURORA_SECTOR_BASE_URL_REQUIRED_TWO_DISTINCT_HTTPS_HOSTS');
      return {aurora:env.DEMO_AURORA_SECTOR_BASE_URL+'/sector.json',brisa:env.DEMO_BRISA_SECTOR_BASE_URL+'/sector.json'};
    };
    export const assertSectorDocuments=async(plan,env,fetchImpl)=>{
      if(env.REJECT_DOCUMENTS)throw Error('SECTOR_DOCUMENT_READBACK_FAILED');
    };
  `);
  const output=join(dir,'unexpected-post');
  writeFileSync(join(home,'tenant-brand-bootstrap.mjs'),`
    import {writeFileSync} from 'node:fs';
    export async function bootstrapTenants(){writeFileSync(${JSON.stringify(output)},'POST');throw Error('UNSAFE_REMOTE_WRITE')}
  `);
  return {dir,home,output};
}
function env(extra={}){
  return {WSO2_LAB_CONFIRM:'CREATE_SYNTHETIC_RESOURCES',WSO2_BASE_URL:'https://localhost:9443/',...extra};
}

test('sector preflight refuses missing hosts before any remote write or journal',async t=>{
  const f=fixture();t.after(()=>rmSync(f.dir,{recursive:true,force:true}));
  const mod=await import(pathToFileURL(join(f.home,'bootstrap-tenant-control-plane.mjs')).href);
  await assert.rejects(mod.execute('all',{env:env(),emit:()=>{}}),/DEMO_AURORA_SECTOR_BASE_URL_REQUIRED/);
  assert.equal(existsSync(f.output),false);
});
test('sector preflight refuses invalid document before any remote write',async t=>{
  const f=fixture();t.after(()=>rmSync(f.dir,{recursive:true,force:true}));
  const mod=await import(pathToFileURL(join(f.home,'bootstrap-tenant-control-plane.mjs')).href);
  await assert.rejects(mod.execute('all',{env:env({DEMO_AURORA_SECTOR_BASE_URL:'https://aurora.example.test',DEMO_BRISA_SECTOR_BASE_URL:'https://brisa.example.test',REJECT_DOCUMENTS:'yes'})}),/SECTOR_DOCUMENT_READBACK_FAILED/);
  assert.equal(existsSync(f.output),false);
});
test('standalone sector-preflight validates without creating any WSO2 resources',async t=>{
  const f=fixture();t.after(()=>rmSync(f.dir,{recursive:true,force:true}));
  const mod=await import(pathToFileURL(join(f.home,'bootstrap-tenant-control-plane.mjs')).href);
  const result=await mod.execute('sector-preflight',{env:env({DEMO_AURORA_SECTOR_BASE_URL:'https://aurora.example.test',DEMO_BRISA_SECTOR_BASE_URL:'https://brisa.example.test'})});
  assert.deepEqual(result,{sectorDocuments:'VERIFIED_READ_ONLY',distinctHosts:true,writes:0});
  assert.equal(existsSync(f.output),false);
});
