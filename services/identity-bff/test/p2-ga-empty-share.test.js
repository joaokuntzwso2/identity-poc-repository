import test from 'node:test';
import assert from 'node:assert/strict';
import { reconcile, ROOT_SCOPES } from '../../../scripts/p2-bootstrap-core.mjs';
const R='5252717e-1024-40f0-89ee-016b513d36f3';
const P='629e590a-9072-406d-95a8-71f0cfc52cbe';
test('live-observed GA empty sharing envelopes remain unverified in a read-only P2 check',async()=>{
  const endpoint='https://localhost:9444/t/aurora.identity.test/o/api/server/v1/organizations';
  let shareReads=0, mutations=0;
  const rootClient=async(method,url)=>{
    assert.equal(method,'GET');
    if(url===endpoint+'/self')return {id:R,type:'TENANT'};
    if(url.startsWith(endpoint+'?'))return {organizations:[{id:P,name:'Verde Logistics',orgHandle:'verde-logistics'}]};
    if(url===endpoint+'/'+P)return {id:P,name:'Verde Logistics',orgHandle:'verde-logistics',parent:{id:R},status:'ACTIVE'};
    throw Error('unexpected root call');
  };
  const result=await reconcile({write:false,
    tokenProvider:{root:async()=>({access_token:'x'.repeat(40),scope:ROOT_SCOPES.join(' ')})},
    rootClientFactory:()=>rootClient,
    partnerClientFactory:()=>{mutations++;throw Error('partner stage must not run');},
    shareApplication:async(id,mode)=>{shareReads++;assert.equal(id,P);assert.equal(mode,'check');
      return {state:'EMPTY_UNVERIFIED',remoteWrites:0,readbackMode:'EMPTY_HTTP_200_NOT_PROOF'};}
  });
  assert.equal(result.applicationSharing,'EMPTY_UNVERIFIED');
  assert.equal(result.liveEvidence,'PENDING');
  assert.equal(shareReads,1);assert.equal(mutations,0);
});
