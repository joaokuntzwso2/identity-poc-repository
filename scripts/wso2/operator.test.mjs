import test from 'node:test';import assert from 'node:assert/strict';
import{createOperatorServer}from'./operator-server.mjs';
// The operator server rejects startup without opt-in; this test imports with the injected local key via runner env.
test('reset requires a non-browser-readable operator secret',async()=>{
 const srv=createOperatorServer({run:async()=>({ok:true})});await new Promise(ok=>srv.listen(0,'127.0.0.1',ok));
 const port=srv.address().port;try{
  const result=await fetch(`http://127.0.0.1:${port}/api/operator/reset`,{method:'POST',headers:{Origin:'http://127.0.0.1:5173','Content-Type':'application/json'},body:JSON.stringify({confirm:'RESET DEMO',scope:'lab-owned-demo'})});
  assert.equal(result.status,403);
  const badOrigin=await fetch(`http://127.0.0.1:${port}/api/operator/reset`,{method:'POST',headers:{Origin:'https://attacker.example','X-Demo-Operator-Key':'anything'},body:'{}'});assert.equal(badOrigin.status,403);
 }finally{await new Promise(ok=>srv.close(ok))}
});
