(async()=>{
 try{
  const [s,h,c]=await Promise.all([fetch('/api/session').then(r=>r.json()),fetch('/api/wso2-status').then(r=>r.json()),fetch('/api/scenarios').then(r=>r.json())]);
  document.getElementById('client-count').textContent=`${h.statuses.filter(v=>v.status==='DISCOVERY_REACHABLE').length} / 4`;
  document.getElementById('session-count').textContent=`${Object.keys(s.logins).length} / 4`;
  document.getElementById('scenario-count').textContent=String(c.length);
  document.getElementById('pairwise-status').textContent=s.pairwise.status==='IDENTIFIER_PREDICATE_MET'?'Predicate OK':'Pendente';
  document.getElementById('pairwise-detail').textContent=JSON.stringify({result:s.pairwise,logins:s.logins},null,2);
  document.getElementById('request-m2m').addEventListener('click',async()=>{
   const response=await fetch('/api/m2m/client-credentials',{method:'POST',headers:{'Content-Type':'application/json','X-CSRF-Token':s.csrf},body:'{}'});
   const data=await response.json();document.getElementById('m2m-result').textContent=JSON.stringify(data,null,2);
  });
 }catch(e){document.getElementById('pairwise-detail').textContent=`Erro real do backend: ${e.message}`;}
})();
