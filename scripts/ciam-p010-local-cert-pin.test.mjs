import test from 'node:test';
import assert from 'node:assert/strict';
import {mkdtempSync, readFileSync, rmSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {execFileSync} from 'node:child_process';
import {X509Certificate,createHash} from 'node:crypto';
import {
 LOCAL_WSO2_TLS_PIN_CONFIRM, LOCAL_WSO2_PORT,
 verifyLocalWso2Certificate, fetchLocalWso2BrowserPin, chromiumPinnedTlsArgs,
} from './ciam-p010-local-cert-pin.mjs';
function fixture(name) {
 const root=mkdtempSync(join(tmpdir(),'p010-local-spki-'));
 const key=join(root,'key.pem'),cert=join(root,'cert.pem');
 try{
  execFileSync('openssl',['req','-x509','-newkey','rsa:2048','-nodes','-days','2',
   '-subj',`/CN=${name}`,'-addext',`subjectAltName=DNS:${name}`,
   '-keyout',key,'-out',cert],{stdio:'ignore',timeout:15000});
  return {root,raw:new X509Certificate(readFileSync(cert)).raw};
 }catch(e){rmSync(root,{recursive:true,force:true});throw e;}
}
const good=fixture('localhost'),wrong=fixture('not-localhost.example');
process.on('exit',()=>{rmSync(good.root,{recursive:true,force:true});rmSync(wrong.root,{recursive:true,force:true});});
test('SPKI of local self-signed cert matches certificate public key (not full certificate)',()=>{
 const pin=verifyLocalWso2Certificate(good.raw);
 const expected=createHash('sha256').update(new X509Certificate(good.raw).publicKey.export({format:'der',type:'spki'})).digest('base64');
 assert.equal(pin.pin,expected);
 assert.match(pin.certificateFingerprintSha256,/^[a-f0-9]{64}$/);
 assert.deepEqual(chromiumPinnedTlsArgs(pin),[`--ignore-certificate-errors-spki-list=${expected}`]);
 assert.equal(pin.peer,'localhost:9444');
});
test('certificate from foreign hostname is refused, even with valid key',()=>{
 assert.throws(()=>verifyLocalWso2Certificate(wrong.raw),/HOSTNAME_NOT_LOCALHOST/);
});
test('certificate expiration and not-yet-valid time are refused',()=>{
 const x=new X509Certificate(good.raw);
 assert.throws(()=>verifyLocalWso2Certificate(good.raw,Date.parse(x.validTo)+100),/EXPIRED_OR_NOT_YET_VALID/);
 assert.throws(()=>verifyLocalWso2Certificate(good.raw,Date.parse(x.validFrom)-100),/EXPIRED_OR_NOT_YET_VALID/);
});
test('malformed, missing, or excessively large certificate is refused',()=>{
 for(const v of [undefined,Buffer.alloc(0),Buffer.alloc(32769),Buffer.from('abc')])
  assert.throws(()=>verifyLocalWso2Certificate(v));
});
test('pin acquisition refuses without explicit consent, without opening a socket',async()=>{
 await assert.rejects(fetchLocalWso2BrowserPin({}),/EXPLICIT_CONFIRMATION_REQUIRED/);
 await assert.rejects(fetchLocalWso2BrowserPin({confirm:'wrong'}),/EXPLICIT_CONFIRMATION_REQUIRED/);
});
test('pin acquisition never permits an alternate port',async()=>{
 await assert.rejects(fetchLocalWso2BrowserPin({confirm:LOCAL_WSO2_TLS_PIN_CONFIRM,port:443}),/UNEXPECTED_PORT/);
 assert.equal(LOCAL_WSO2_PORT,9444);
});
test('rejects malformed or forged pin, never uses global no-verify switches',()=>{
 for(const v of [null,{}, {peer:'localhost:9444',pin:'x'}, {peer:'evil:9444',pin:'A'.repeat(43)+'='}])
  assert.throws(()=>chromiumPinnedTlsArgs(v),/INVALID_LOCAL_WSO2_TLS_SPKI_PIN/);
 const args=chromiumPinnedTlsArgs(verifyLocalWso2Certificate(good.raw));
 assert.equal(args.length,1);
 assert.ok(!args.some(x=>x==='--ignore-certificate-errors'||x==='--allow-insecure-localhost'));
});
