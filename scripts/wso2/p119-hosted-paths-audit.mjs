import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import crypto from 'node:crypto';
import {createRequire} from 'node:module';

const ORIGIN='https://localhost:9444';
const BFF='http://127.0.0.1:4400';
const DOMAINS={aurora:'aurora.identity.test',brisa:'brisa.identity.test'};
const EXPECTED='2ba361a032ffd4b34f7df066de72b61c5e836a09f7a7bd7105eb87b4094d9712';
const FAIL=code=>{throw Error(code)};

function allowed(url,method){
  try {
    const u=new URL(url);
    return ['GET','HEAD'].includes(method)&&!u.username&&!u.password&&
      (u.origin===ORIGIN||u.origin===BFF);
  } catch {return false;}
}

function pinned(){
  const p=path.join(os.homedir(),
    'Library/Application Support/ciam-p118-p119-lab-trust/wso2-issuer-9444.pem');
  const s=fs.lstatSync(p);
  if(!s.isFile()||s.isSymbolicLink()||s.size>65536)FAIL('INVALID_CERT');
  const cert=new crypto.X509Certificate(fs.readFileSync(p));
  if(cert.checkHost('localhost')!=='localhost'||
    Date.parse(cert.validFrom)>Date.now()||
    Date.parse(cert.validTo)<=Date.now()||
    crypto.createHash('sha256').update(cert.raw).digest('hex')!==EXPECTED)
      FAIL('CERT_PIN_MISMATCH');
  return crypto.createHash('sha256')
    .update(cert.publicKey.export({type:'spki',format:'der'}))
    .digest('base64');
}

function safeCandidate(raw,at,domain){
  try {
    const u=new URL(raw,at);
    if(u.origin!==ORIGIN||u.username||u.password||u.hash)return null;
    const prefix=`/t/${domain}/accountrecoveryendpoint/`;
    const shared='/accountrecoveryendpoint/';
    if(!u.pathname.startsWith(prefix)&&!u.pathname.startsWith(shared))
      return null;
    const segment=u.pathname.startsWith(prefix)
      ?u.pathname.slice(prefix.length):u.pathname.slice(shared.length);
    if(!/^[a-zA-Z0-9_./-]{1,120}$/.test(segment)||segment.includes('..'))
      return null;
    return {path:u.pathname,has_query:!!u.search};
  } catch {return null;}
}

function kind(label,pathname){
  const base=pathname.toLowerCase().split('/').pop();
  if(/register|sign.?up|create\s+account|cadast/i.test(label)||
    /register|signup/.test(base))return 'registration';
  if(/forgot|recover|reset|esqueceu|recuperar/i.test(label)||
    /recover|reset|forgot/.test(base))return 'recovery';
  return null;
}

async function inspect(browser,target,domain,cache){
  const context=await browser.newContext({
    ignoreHTTPSErrors:false,acceptDownloads:false,serviceWorkers:'block'
  });
  await context.route('**/*',route=>
    allowed(route.request().url(),route.request().method())
      ?route.continue():route.abort()
  );
  const page=await context.newPage();
  page.on('dialog',d=>d.dismiss().catch(()=>{}));
  const result={page_http:'NOT_REACHED',links:[]};

  try {
    const res=await page.goto(target,{
      waitUntil:'domcontentloaded',timeout:25000
    });
    await page.waitForTimeout(900);
    result.page_http=res?.status()??'NO_HTTP';

    const links=await page.locator('a[href]').evaluateAll(xs=>
      xs.slice(0,100).map(x=>{
        const style=getComputedStyle(x);
        return {
          href:x.getAttribute('href')||'',
          label:[
            x.textContent||'',
            x.getAttribute('aria-label')||'',
            x.getAttribute('title')||''
          ].join(' ').slice(0,160),
          visible:!!x.getClientRects().length&&
            style.visibility!=='hidden'&&style.display!=='none'
        };
      })
    );

    for(const link of links){
      const candidate=safeCandidate(link.href,page.url(),domain);
      if(!candidate)continue;
      const role=kind(link.label,candidate.path);
      if(!role)continue;

      const entry={
        role,visible:link.visible,
        path:candidate.path,has_query:candidate.has_query
      };

      if(!cache.has(candidate.path)){
        const probe=await context.newPage();
        try {
          const response=await probe.goto(
            ORIGIN+candidate.path,{
              waitUntil:'domcontentloaded',timeout:12000
            }
          );
          await probe.waitForTimeout(350);
          const final=new URL(probe.url());
          const text=await probe.locator('body')
            .innerText({timeout:3000}).catch(()=>'');

          cache.set(candidate.path,{
            http:response?.status()??'NO_HTTP',
            final_page:final.origin!==ORIGIN?'OTHER_ORIGIN':
              final.pathname.includes('accountrecoveryendpoint')
                ?'RECOVERY_PORTAL':
              final.pathname.includes('authenticationendpoint')
                ?'LOGIN_PAGE':'OTHER_WSO2_PAGE',
            form_count:await probe.locator('form').count(),
            registration_marker:
              /register|sign\s*up|create\s+account/i.test(text),
            recovery_marker:
              /forgot|recover|reset\s+password/i.test(text)
          });
        } catch {
          cache.set(candidate.path,{http:'NAVIGATION_FAILED'});
        } finally {
          await probe.close();
        }
      }

      entry.queryless_get=cache.get(candidate.path);

      if(!result.links.some(x=>
        x.role===entry.role&&x.path===entry.path&&
        x.visible===entry.visible
      ))result.links.push(entry);
    }
  } catch {
    result.page_http='NAVIGATION_FAILED';
  } finally {
    await context.close();
  }
  return result;
}

async function main(){
  const pkg=path.join(process.cwd(),'package.json');
  if(!fs.existsSync(pkg)||!fs.existsSync(path.join(
    process.cwd(),'services/identity-bff/src/server.js'
  )))FAIL('WRONG_REPO');

  const require=createRequire(pkg);
  let chromium;
  for(const n of ['playwright','@playwright/test','playwright-core']){
    try {chromium=require(n).chromium;if(chromium)break;}
    catch {}
  }
  if(!chromium)FAIL('PLAYWRIGHT_UNAVAILABLE');

  const browser=await chromium.launch({
    headless:true,
    args:['--ignore-certificate-errors-spki-list='+pinned()]
  });
  const results={},cache=new Map();

  try {
    for(const [brand,domain] of Object.entries(DOMAINS)){
      results[brand+'-myaccount']=await inspect(
        browser,ORIGIN+`/t/${domain}/myaccount`,domain,cache
      );
      for(const channel of ['web','app']){
        results[brand+'-'+channel]=await inspect(
          browser,BFF+`/auth/${brand}-${channel}/login`,domain,cache
        );
      }
    }
  } finally {
    await browser.close();
  }

  console.log(JSON.stringify({
    status:'P119_HOSTED_PATHS_GET_ONLY',
    tls:'CERTIFICATE_FINGERPRINT_VERIFIED_SPKI_SCOPED_BROWSER',
    link_query_values_logged:false,
    all_requests:'GET_OR_HEAD',
    forms_submitted:false,
    account_writes:false,
    urls:results
  },null,2));
}

main().catch(e=>{
  console.error('P119_STOP:',
    /^(WRONG_REPO|PLAYWRIGHT_UNAVAILABLE|CERT_PIN_MISMATCH|INVALID_CERT)$/
      .test(e.message)?e.message:'AUDIT_FAILED');
  process.exitCode=2;
});
