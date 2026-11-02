#!/usr/bin/env node
/** P1.23: read-only default, fail closed. No bootstrap/migration/business mutations. */
import { createHash } from 'node:crypto';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { readFile, readdir, mkdir, writeFile, stat } from 'node:fs/promises';
import { homedir } from 'node:os';
import { dirname, join, resolve, sep } from 'node:path';
import { fileURLToPath } from 'node:url';
import { createRequire } from 'node:module';
import { createInterface } from 'node:readline/promises';
const run = promisify(execFile);
const root=resolve(dirname(fileURLToPath(import.meta.url)),'..');
const args=new Set(process.argv.slice(2));
const getArg=(flag)=>{const i=process.argv.indexOf(flag);return i>=0?process.argv[i+1]:undefined;};
const offline=args.has('--offline');
const browserOff=args.has('--no-browser');
const rehearse=args.has('--rehearse');
const deep=args.has('--deep-readback');
const expected=getArg('--expected-commit')||process.env.DEMO_EXPECTED_COMMIT||null;
const origin=process.env.DEMO_BFF_ORIGIN||'http://127.0.0.1:4400';
const channels=[
  ['aurora-web','aurora','/portal/aurora/web'],['aurora-app','aurora','/portal/aurora/mobile'],
  ['brisa-web','brisa','/portal/brisa/web'],['brisa-app','brisa','/portal/brisa/mobile']
];
const results=[];const safe=(text)=>String(text).slice(0,180).replace(/[\r\n\x00-\x1f]/g,' ');
const add=(id,status,detail,kind='GATE')=>results.push({id,status,detail:safe(detail),kind});
const command=async(file,argv,{timeout=90000}={})=>{
  try{ const r=await run(file,argv,{cwd:root,timeout,maxBuffer:1048576,env:process.env});
    return {ok:true,stdout:r.stdout,stderr:r.stderr};
  }catch(e){return {ok:false,exitCode:e.code||'UNKNOWN'};}
};
const load=async(path)=>readFile(join(root,path)).catch(()=>null);
const sha=(bytes)=>bytes?createHash('sha256').update(bytes).digest('hex'):null;
const http=async(path)=>{
  try{const r=await fetch(new URL(path,origin),{signal:AbortSignal.timeout(5500),headers:{Accept:'application/json'},redirect:'manual'});
    const body=await r.json().catch(()=>({}));return {status:r.status,body};
  }catch{return {status:0,body:{}};}
};
const repoHash=await command('git',['rev-parse','HEAD']);
const commit=repoHash.ok?repoHash.stdout.trim():null;
add('source.commit',commit?'PASS':'FAIL',commit||'Checkout Git SHA unavailable');
const gitRemote=await command('git',['remote','get-url','origin']);
const remoteOk=gitRemote.ok && /(?:github\.com[:/])joaokuntzwso2\/identity-poc-repository(?:\.git)?\s*$/.test(gitRemote.stdout.trim());
add('source.repository',remoteOk?'PASS':'FAIL',remoteOk?'Expected public repository origin confirmed':'Repository remote does not match expected owner/name');
const gitStatus=await command('git',['status','--porcelain=v1','--untracked-files=normal']);
add('source.working_tree',gitStatus.ok&&gitStatus.stdout.trim()===''?'PASS':'FAIL',gitStatus.ok?(gitStatus.stdout.trim()?`${gitStatus.stdout.trim().split('\n').length} changes/untracked paths; commit the verified release`:'clean'):'git status failed');
add('source.expected_release',!expected?'BLOCKED':commit===expected?'PASS':'FAIL',!expected?'Set DEMO_EXPECTED_COMMIT to an approved full Git SHA':commit===expected?'Approved Git SHA matches':'Approved SHA does not match checkout');
const pkg=await load('package.json');
const html=await load('services/identity-bff/src/live-experience-v5.html');
const frontend=await load('services/identity-bff/src/live-premium-p120.js');
const css=await load('services/identity-bff/src/live-premium-p120.css');
add('source.premium_assets',pkg&&html&&frontend&&css&&html.toString().includes('/live-premium-p120.js')?'PASS':'FAIL','P1.20 assets and route integration');
const readme=await load('README.md');
add('docs.root_authority',readme?.toString().includes('P1.20–P1.23 — Demo operations')?'PASS':'FAIL','Root README current operational contract');
const sourceFiles={};
for(const name of ['server.js','live-experience-v5.js','live-experience-v5.html','live-premium-p120.js','live-premium-p120.css']) {
  sourceFiles[name]=sha(await load('services/identity-bff/src/'+name));
}
let leak=false;
const tracked=await command('git',['ls-files','-z']);
if(tracked.ok){
  const paths=tracked.stdout.split('\0').filter(Boolean);
  for(const p of paths){
    if(/(?:^|\/)(?:private|secrets?|\.env(?:\.|$)|id_rsa$)/i.test(p) && !/(?:^|\/)\.env\.(?:example|sample|template)$/.test(p)){leak=true;break;}
    if(/\.(?:pem|key|p12|pfx)$/i.test(p)){leak=true;break;}
    if(!/\.(?:js|mjs|ts|tsx|json|md|sh|py|html|txt|ya?ml|toml)$/i.test(p))continue;
    const data=await load(p);if(!data)continue;
    if(/-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----/.test(data.toString())){leak=true;break;}
  }
}
add('security.tracked_secrets',!tracked.ok?'BLOCKED':leak?'FAIL':'PASS',!tracked.ok?'Git index not readable':leak?'Potential private material in tracked sources; inspect locally':'No tracked private filenames/PEM key blocks detected (not a full secret scan)');
const privateRoot=resolve(process.env.CIAM_V10_HOME||join(homedir(),'wso2-ciam-v10'),'private');
try{
  const s=await stat(join(privateRoot,'bootstrap-identities-v10.private.json'));
  add('identities.private_journal',(s.mode&0o077)===0?'PASS':'FAIL',(s.mode&0o077)===0?'Private identity journal exists with restrictive permissions':'Private identity journal is accessible to group/others');
}catch{add('identities.private_journal','BLOCKED','Private identity journal not found; credentials cannot be verified');}
const script=await load('scripts/ciam-identity-ops.py');
add('identities.credential_workflow',script?'PASS':'BLOCKED','macOS clipboard retrieval requires locally verified journal and WSO2 login; passwords are not read by preflight');
const offlineCommands=[
 ['offline.bff_unit','node',[],true],
 ['offline.p120_contract','node',['--test','tests/p120-contract.test.mjs'],false],
 ['offline.scenarios','node',['scripts/preflight.mjs'],false],
 ['offline.zero_mock','python3',['scripts/zero-mock-gate.py','.'],false]
];
// Shell glob expansion is intentionally avoided: node --test accepts a directory of .test.js files via discovery.
for(const [id,exe,argv,glob] of offlineCommands){
  const testPaths=glob?(await readdir(join(root,'services/identity-bff/test')).catch(()=>[])).filter(f=>f.endsWith('.test.js')).map(f=>'services/identity-bff/test/'+f):null;
  const useArg=glob?['--test',...(testPaths||[])]:argv;
  const r=testPaths?.length===0?{ok:false,exitCode:'NO_TESTS'}:await command(exe,useArg,{timeout:180000});
  add(id,r.ok?'PASS':'FAIL',r.ok?'Offline command exited 0':`Offline command failed (${safe(r.exitCode)})`,'OFFLINE');
}
let discovery=null, health=null, identity=null;
if(offline){
  add('live.wso2_discovery','BLOCKED','Offline mode; no live authority call');
  add('runtime.provenance','BLOCKED','Offline mode; live BFF provenance unavailable');
}else{
  [health,discovery,identity]=await Promise.all([http('/api/health'),http('/api/wso2-status'),http('/api/identity/me')]);
  add('live.bff_health',health.status===200&&health.body.status==='UP'?'PASS':'FAIL',`BFF /api/health HTTP ${health.status||'unreachable'}`);
  const statuses=discovery.body.statuses;
  const all=discovery.status===200&&discovery.body.identityMode==='live-wso2'&&
    channels.every(([key])=>Array.isArray(statuses)&&statuses.some(s=>s.key===key&&s.discovery===true));
  add('live.wso2_discovery',all?'PASS':'FAIL',all?'Four tenant-specific OIDC discoveries responded':'One or more issuer discoveries unavailable or unverified');
  const p=health.body.provenance;
  const verified=p&&p.commit&&p.commit===commit&&Object.entries(sourceFiles).every(([name,digest])=>digest&&p.files?.[name]===digest);
  add('runtime.provenance',verified?'PASS':'FAIL',verified?'Running BFF startup SHA and source asset digests match checkout':'Running BFF lacks matching startup provenance/digests; restart after deploying and compare');
  add('live.browser_session','BLOCKED',
    'Anonymous preflight cookies never establish OIDC login. Authenticate each channel in a real browser.');
}
if(deep&&!offline){
  const readbacks=[
    ['live.client_readback','python3',['scripts/ciam-v5-four-client-readback.py']],
    ['live.business_readback','python3',['deploy/ciam-v10/phase4/business-bootstrap.py','verify']],
    ['live.carbon_super','python3',['scripts/ciam-carbon-super-readback.py']]
  ];
  for(const [id,exe,argv] of readbacks){
    const r=await command(exe,argv,{timeout:90000});
    add(id,r.ok?'BLOCKED':'FAIL',r.ok?'Read-only command exited 0; inspect its management readback (exit code alone does not prove all resources)':'Read-only command failed');
  }
}else{add('live.management_readback','BLOCKED','Run --deep-readback for read-only inventory calls; exact scopes, apps, roles, audiences remain unverified');}
let pw=null, axePath=null;
if(!browserOff&&!offline){
  try{
    const require=createRequire(import.meta.url);
    const paths=[root,join(root,'apps/experience-center')];
    pw=require(require.resolve('@playwright/test',{paths}));
    try {axePath=require.resolve('axe-core/axe.min.js',{paths});}catch { /* Optional audited dependency */ }
  }catch{add('browser.runner','BLOCKED','@playwright/test unavailable; run npm install and install Chromium in local checkout');}
}
if(pw){
  let browser;
  try{
    // Anonymous viewport/link/axe checks are always headless. Never flash 25 windows
    // before the operator is able to complete an OIDC login.
    browser=await pw.chromium.launch({headless:true});
    const urls=['/lab',...channels.map(c=>c[2])];const sizes=[320,375,768,1280,1600];
    let failed=0, pages=0, screenshots=0, axeExecuted=0, axeViolations=0, axeUnavailable=0;
    const axeFailureKinds=new Set();
    const screenshotsDir=join(homedir(),'Downloads','ciam-demo-evidence','screenshots');
    await mkdir(screenshotsDir,{recursive:true,mode:0o700});
    for(const url of urls){
      for(const width of sizes){
        const context=await browser.newContext({viewport:{width,height:900},deviceScaleFactor:1});
        // Init scripts execute before application JS and work under restrictive CSP where
        // addScriptTag({path}) may be blocked. No network/CDN or application tokens involved.
        let axeInitError=null;
        if(axePath){try{await context.addInitScript({path:axePath});}
          catch(e){axeInitError=e?.name||'INIT_ERROR';}}
        const page=await context.newPage();
        try{
          const response=await page.goto(origin+url,{waitUntil:'domcontentloaded',timeout:18000});
          await page.locator('#main-content').waitFor({timeout:12000});
          if (axePath) {
            try{
              if(axeInitError)throw Error('AXE_INIT_ERROR');
              const audit=await page.evaluate(async()=>{
                if(!window.axe||typeof window.axe.run!=='function')return {error:'AXE_NOT_AVAILABLE'};
                const report=await window.axe.run(document,{runOnly:{type:'tag',values:['wcag2a','wcag2aa','wcag21aa','wcag22aa']}});
                return {violations:report.violations.length};
              });
              if(audit.error)throw Error(audit.error);
              axeExecuted++;axeViolations+=audit.violations;
            }catch(e){
              axeUnavailable++;
              // Report only a bounded error category, not URLs, subjects, tokens or page content.
              const message=String(e?.message||'');
              axeFailureKinds.add(message.includes('AXE_NOT_AVAILABLE')?'AXE_NOT_AVAILABLE':
                message.includes('AXE_INIT_ERROR')?'AXE_INIT_ERROR':
                /Content Security Policy|CSP/i.test(message)?'CSP':
                /Timeout/i.test(message)?'TIMEOUT':'AUDIT_EXCEPTION');
            }
          }
          const checks=await page.evaluate(()=>{
            const overflow=document.documentElement.scrollWidth>innerWidth+2;
            const all=[...document.querySelectorAll('button,input,textarea,select')];
            const unlabelled=all.filter(e=>{
              if(e.hasAttribute('disabled'))return false;
              const label=e.getAttribute('aria-label')||e.getAttribute('title')||e.textContent?.trim()||e.labels?.[0]?.textContent?.trim();
              return !label;
            }).length;
            const links=[...document.querySelectorAll('a[href]')];
            const dead=links.filter(a=>{const h=a.getAttribute('href');return h==='#'||h==='javascript:void(0)'||h==='';}).length;
            const ids=[...document.querySelectorAll('[id]')].map(e=>e.id);
            return {overflow,unlabelled,dead,duplicateIds:ids.length-new Set(ids).size,main:!!document.querySelector('#main-content'),
              linkTargets:[...new Set(links.map(a=>a.getAttribute('href')||'').filter(h=>h.startsWith('/')&&!h.startsWith('//')).map(h=>h.split('#')[0].split('?')[0]))]};
          });
          pages++;
          let invalidLinks=0;
          if(width===1280){
            for(const target of checks.linkTargets){
              if(/^\/auth\/(aurora|brisa)-(web|mobile|app)\/login$/.test(target))continue; // Never start OIDC for an anonymous link audit.
              const valid=['/','/lab','/experience',...channels.map(c=>c[2])].includes(target);
              if(!valid){invalidLinks++;continue;}
              const linked=await page.request.get(origin+target,{maxRedirects:0,timeout:4500}).catch(()=>null);
              if(linked?.status()!==200)invalidLinks++;
            }
          }
          if(response?.status()!==200||checks.overflow||checks.unlabelled||checks.dead||checks.duplicateIds||!checks.main||invalidLinks)failed++;
          if(width===375||width===1280){
            const clean=url.replace(/\W/g,'-')||'root';
            await page.screenshot({path:join(screenshotsDir,`${clean}-${width}.png`),fullPage:true}); screenshots++;
          }
        }catch{failed++;}
        finally{await context.close();}
      }
    }
    add('browser.responsive_and_links',failed?'FAIL':'PASS',`${pages}/${urls.length*sizes.length} page/width checks ran; ${failed} issues; ${screenshots} anonymous screenshots`, 'BROWSER');
    add('accessibility.axe_core',!axePath||axeUnavailable||axeExecuted<urls.length*sizes.length?'BLOCKED':axeViolations?'FAIL':'PASS',
      !axePath?'axe-core not installed (npm install --no-save --package-lock=false axe-core)':`WCAG 2.0/2.1/2.2 AA rules: ${axeExecuted} pages audited, ${axeViolations} violation categories, ${axeUnavailable} audits unavailable; failure categories: ${[...axeFailureKinds].join(', ')||'none'}`,'BROWSER');
    if(rehearse){
      // A TTY is required: unattended CI must never claim human-authenticated proof.
      if(!process.stdin.isTTY || !process.stdout.isTTY){
        for(const [key] of channels)
          add(`rehearsal.${key}`,'BLOCKED','Interactive terminal required for supervised WSO2 login','LIVE_BROWSER');
      }else{
        let operatorBrowser=null;
        const prompt=createInterface({input:process.stdin,output:process.stdout});
        let aborted=false;
        try{
          // This is a SEPARATE visible browser. No timer automatically closes a login.
          operatorBrowser=await pw.chromium.launch({headless:false});
          for(const [key,brand,path] of channels){
            if(aborted){
              add(`rehearsal.${key}`,'BLOCKED','Operator stopped the remaining rehearsal','LIVE_BROWSER');
              continue;
            }
            const context=await operatorBrowser.newContext({viewport:{width:1280,height:900}});
            const page=await context.newPage();
            const auth=key.endsWith('-app')?`${brand}-mobile`:key;
            const loginUrl=`${origin}/auth/${auth}/login?returnTo=${encodeURIComponent(path)}`;
            console.log(`\nWSO2 OPERATOR REHEARSAL: ${key}`);
            console.log('Complete the real WSO2 login in the visible window.');
            console.log('Do not type passwords, codes, tokens or private user data in this terminal.');
            try{
              try{await page.goto(loginUrl,{waitUntil:'domcontentloaded',timeout:30000});}
              catch{console.log('Initial navigation did not finish. Inspect the browser (including local TLS trust) and retry manually.');}
              await page.bringToFront();
              let finished=false;
              while(!finished){
                const action=(await prompt.question(`[${key}] After login returns to the BFF, press Enter to verify; r=retry login, s=skip, q=stop: `)).trim().toLowerCase();
                if(action==='s'||action==='q'){
                  add(`rehearsal.${key}`,'BLOCKED',action==='q'?'Operator stopped rehearsal':'Operator skipped authentication','LIVE_BROWSER');
                  aborted=action==='q';finished=true;continue;
                }
                if(action==='r'){
                  try{await page.goto(loginUrl,{waitUntil:'domcontentloaded',timeout:30000});}
                  catch{console.log('Navigation not complete. Browser remains open for inspection.');}
                  continue;
                }
                if(action!==''){console.log('Choose Enter, r, s or q.');continue;}
                let current;
                try{current=new URL(page.url());}catch{current=null;}
                if(current?.origin!==new URL(origin).origin){
                  console.log('The browser has not returned to the local BFF. Finish authentication or choose s to skip.');
                  continue;
                }
                // Some valid BFF callbacks land on /lab rather than the portal. Navigate
                // within the SAME authenticated browser context before protected readback.
                try{
                  if(current.pathname!==path)await page.goto(new URL(path,origin).href,{waitUntil:'domcontentloaded',timeout:18000});
                  const proof=await page.evaluate(async({key,brand})=>{
                    const get=async(url)=>{const r=await fetch(url,{credentials:'same-origin',cache:'no-store'});return {http:r.status,body:await r.json().catch(()=>({}))};};
                    const me=await get('/api/identity/me');const c=me.body.clients?.[key];
                    const other=brand==='aurora'?'brisa':'aurora';
                    const p=await get(`/api/brands/${brand}/profile?client=${key}`);
                    const list=await get(`/api/brands/${brand}/cases?client=${key}`);
                    const denied=await get(`/api/brands/${other}/cases?client=${key}`);
                    return {authenticated:c?.authenticated===true,issuerMatches:(()=>{try{const i=new URL(c?.issuer);return i.protocol==='https:'&&i.hostname==='localhost'&&i.port==='9444'&&i.pathname.includes(`/t/${brand}.identity.test/`);}catch{return false;}})(),
                      profileScope:(c?.permissions||[]).includes('ciam:profile:read'),
                      profileHTTP:p.http,casesHTTP:list.http,visibility:list.body.visibility||null,denialHTTP:denied.http};
                  },{key,brand});
                  if(!proof.authenticated){
                    console.log('No authenticated session for this client was proven. Browser remains open; retry or skip.');
                    continue;
                  }
                  const passed=proof.issuerMatches&&proof.profileScope&&proof.profileHTTP===200&&
                    proof.casesHTTP===200&&proof.visibility==='OWNER_ONLY'&&proof.denialHTTP===403;
                  const detail=`OIDC=true, issuer=${proof.issuerMatches}, profileScope=${proof.profileScope}, profile=${proof.profileHTTP}, cases=${proof.casesHTTP}, visibility=${proof.visibility}, cross-tenant=${proof.denialHTTP}`;
                  add(`rehearsal.${key}`,passed?'PASS':'FAIL',detail,'LIVE_BROWSER');
                  console.log(`${key}: ${passed?'PASS':'FAIL'} — ${detail}`);
                  finished=true; // Browser closes only AFTER this explicit verification attempt.
                }catch{
                  console.log('Protected readback could not complete. Browser remains open; retry or skip.');
                }
              }
            }finally{await context.close();}
          }
        }catch{
          for(const [key] of channels){
            if(!results.some(r=>r.id===`rehearsal.${key}`))
              add(`rehearsal.${key}`,'BLOCKED','Operator browser unavailable or interrupted','LIVE_BROWSER');
          }
        }finally{prompt.close();await operatorBrowser?.close();}
      }
    }else{add('rehearsal.four_oidc','BLOCKED','Operator-authenticated OIDC flows not run; use --rehearse with authorized test identities','LIVE_BROWSER');}
  }catch{add('browser.runner','BLOCKED','Playwright browser unavailable, not a successful accessibility or responsive run','BROWSER');}
  finally{await browser?.close();}
}else{add('browser.coverage','BLOCKED','No browser proof executed; not equivalent to tested responsive/accessibility interactions','BROWSER');
  add('accessibility.axe_core','BLOCKED','No browser and axe-core audit executed','BROWSER');}
add('accessibility.wcag_22_aa','BLOCKED','Automated heuristics do not constitute axe-core and manual keyboard/AT/contrast WCAG 2.2 AA acceptance','BROWSER');
add('business.persistence','BLOCKED','No business mutations in non-destructive preflight; create/read and seller-approval persistence require separate authorized rehearsal','LIVE_BROWSER');
add('mfa.positive_approval','BLOCKED','No validated positive TOTP approval/persistence proof in this run','LIVE_BROWSER');
add('mfa.negative_approval','BLOCKED','No fresh authenticated seller negative approval proof in this run','LIVE_BROWSER');
add('database.consistency','BLOCKED','Non-destructive checks did not verify case ledger fsync, cross-process consistency or backups');
let decision=results.some(r=>r.status==='FAIL')?'NOT_READY':results.some(r=>r.status==='BLOCKED')?'BLOCKED':'READY';
const report={schema:'CIAM_DEMO_PREFLIGHT_V1',runAt:new Date().toISOString(),decision,
  source:{commit,expectedCommit:expected,clean:gitStatus.ok&&gitStatus.stdout.trim()==='',origin},
  mode:{offline,browserEnabled:!browserOff,operatorRehearsal:rehearse,deepReadback:deep},
  // No secret values, private subject attributes, session headers or API response bodies.
  results};
const dir=resolve(getArg('--output-dir')||join(homedir(),'Downloads','ciam-demo-evidence'));
if(dir===root||dir.startsWith(root+sep))throw Error('Evidence must be written outside the Git checkout');
await mkdir(dir,{recursive:true,mode:0o700});
const stamp=report.runAt.replace(/[:.]/g,'-');
const file=join(dir,`preflight-${stamp}.json`);
await writeFile(file,JSON.stringify(report,null,2)+'\n',{mode:0o600});
const mdFile=file.replace(/\.json$/,'.md');
const md=['# CIAM executive demonstration readiness',`Decision: **${decision}**`,`Date: ${report.runAt}`,
  `Source commit: ${commit||'unavailable'}`,`Approved commit: ${expected||'not configured'}`,
  `Live BFF provenance: ${results.find(r=>r.id==='runtime.provenance')?.status||'unavailable'}`,
  '', '| Decision | Gate | Evidence summary |','|---|---|---|',
  ...results.map(r=>`| ${r.status} | \`${r.id}\` | ${r.detail.replace(/\|/g,'/')} |`),
  '', 'BLOCKED means a verification was not executed or not substantiated; it is never a pass.',
  'Credentials, bearer tokens, cookies, subject attributes, and CSRF are not recorded.'];
await writeFile(mdFile,md.join('\n')+'\n',{mode:0o600});
console.log(`\nCIAM EXECUTIVE DEMO READINESS: ${decision}`);
console.log(`Git: ${commit||'UNAVAILABLE'} | approved: ${expected||'NOT SET'} | tree: ${report.source.clean?'clean':'not clean'}`);
console.log(`Offline ${results.filter(r=>r.kind==='OFFLINE'&&r.status==='PASS').length}/${results.filter(r=>r.kind==='OFFLINE').length} passed; live browser proof ${results.filter(r=>r.kind==='LIVE_BROWSER'&&r.status==='PASS').length} verified`);
for(const r of results.filter(r=>r.status!=='PASS')) console.log(`- ${r.status} ${r.id}: ${r.detail}`);
console.log(`Sanitized technical evidence: ${file}`);
console.log(`Executive summary: ${mdFile}`);
process.exitCode=decision==='READY'?0:decision==='NOT_READY'?2:3;
