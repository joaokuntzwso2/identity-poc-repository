'use strict';
// The browser never receives WSO2 secrets or tokens; render only sanitized data.
const $=id=>document.getElementById(id);
const notice=s=>{$('notice').textContent=s;};
let csrf='';
const el=(tag,cls,text)=>{const x=document.createElement(tag);if(cls)x.className=cls;
  if(text!==undefined)x.textContent=String(text);return x;};
async function json(url,body=null,headers={}){
  const r=await fetch(url,{method:body===null?'GET':'POST',credentials:'same-origin',
    cache:'no-store',redirect:'error',headers:{...(body===null?{}:
      {'Content-Type':'application/json'}),...headers},
    ...(body===null?{}:{body:JSON.stringify(body)})});
  const v=await r.json();if(!r.ok)throw Error(v.code||'HTTP_'+r.status);return v;
}
function render(s){
  csrf=s.csrf||csrf;
  $('metrics').replaceChildren();
  for(const [title,value] of [['Observed WSO2 users',s.observedUserCount??'—'],
    ['Lifecycle member',s.lifecycleUser?.phase||'not created'],
    ['Business group',s.businessGroup?.phase||'not created'],
    ['Membership',s.membershipPhase||'none']]){
    const x=el('div','metric');x.append(el('strong','',value),el('span','',title));
    $('metrics').append(x);
  }
  $('phase').textContent='Verde organization: '+s.partnerId+
    ' · Delegated create/list · Owner-approved group/offboarding';
  $('users').replaceChildren(el('h3','','Live WSO2 user inventory (no email/password shown)'));
  for(const user of s.observedUsers||[]){
    $('users').append(el('div','record',(user.username||'Unknown')+
      ' · '+(user.active?'active':'inactive')+' · '+user.id));
  }
  $('evidence').replaceChildren();
  for(const row of s.eventEvidence||[]){
    $('evidence').append(el('div','record good',row.at+' · '+row.event+' · '+row.source));
  }
  if(!(s.eventEvidence||[]).length)
    $('evidence').append(el('p','muted','No lifecycle event has been verified yet.'));
}
async function refresh(){
  try{notice('Reading WSO2…');const s=await json('/api/state');render(s);
    notice('Live WSO2 readback completed.');}
  catch(e){notice('BLOCKED: '+e.message+'. No success is assumed.');}
}
$('login-form').addEventListener('submit',async e=>{
  e.preventDefault();
  try{const r=await json('/api/login',{code:$('code').value});csrf=r.csrf;
    $('code').value='';$('login').hidden=true;$('dashboard').hidden=false;
    await refresh();}
  catch(e){notice('Login blocked: '+e.message);}
});
$('refresh').addEventListener('click',refresh);
for(const button of document.querySelectorAll('[data-action]')){
  button.addEventListener('click',async()=>{
    const action=button.dataset.action;
    const phrase=action==='deactivate'?'DEACTIVATE':'VERDE';
    const ok=window.prompt('Confirm '+action+' by typing '+phrase+
      ' (only the journal-owned lab resource is eligible):');
    if(ok!==phrase)return;
    button.disabled=true;
    notice('Request sent. No automatic retries on uncertain WSO2 writes.');
    try{const result=await json('/api/action',{action,confirm:ok},
      {'X-CSRF-Token':csrf});
      notice(result.status+' — '+action+'. Refreshing WSO2 readback…');
      await refresh();}
    catch(e){notice('BLOCKED: '+e.message+'. Inspect journal/readback before retry.');}
    finally{button.disabled=false;}
  });
}
