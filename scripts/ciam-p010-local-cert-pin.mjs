/** Loopback-only TLS trust bootstrap for operator-assisted WSO2 E2E browser tests.
 * Never disables HTTPS verification globally. Uses Chromium's SPKI allowlist.
 * The peer identity is bootstrapped from the loopback WSO2 endpoint; this is
 * test-only TOFU, not a substitute for enterprise CA / pre-provisioned pins.
 */
import { connect as tlsConnect } from 'node:tls';
import { X509Certificate, createHash } from 'node:crypto';

export const LOCAL_WSO2_TLS_PIN_CONFIRM = 'TRUST_CURRENT_LOCAL_WSO2_CERTIFICATE_FOR_BROWSER_TEST';
export const LOCAL_WSO2_PORT = 9444;

export function verifyLocalWso2Certificate(raw, now = Date.now()) {
  if (!Buffer.isBuffer(raw) || raw.length === 0 || raw.length > 32768)
    throw new Error('LOCAL_WSO2_TLS_CERTIFICATE_MISSING_OR_OVERSIZED');
  const cert = new X509Certificate(raw);
  if (!cert.checkHost('localhost'))
    throw new Error('LOCAL_WSO2_TLS_CERTIFICATE_HOSTNAME_NOT_LOCALHOST');
  const notBefore = Date.parse(cert.validFrom);
  const notAfter = Date.parse(cert.validTo);
  if (!Number.isFinite(notBefore) || !Number.isFinite(notAfter) || now < notBefore || now >= notAfter)
    throw new Error('LOCAL_WSO2_TLS_CERTIFICATE_EXPIRED_OR_NOT_YET_VALID');
  const spki = cert.publicKey.export({ format: 'der', type: 'spki' });
  return {
    pin: createHash('sha256').update(spki).digest('base64'),
    certificateFingerprintSha256: cert.fingerprint256.replaceAll(':','').toLowerCase(),
    peer: 'localhost:9444',
    trustScope: 'CHROMIUM_SPKI_ONLY_FOR_THIS_BROWSER_RUN',
  };
}

export async function fetchLocalWso2BrowserPin({confirm, timeoutMs=7000, port=LOCAL_WSO2_PORT}={}) {
  if (confirm !== LOCAL_WSO2_TLS_PIN_CONFIRM)
    throw new Error('LOCAL_WSO2_TLS_PIN_EXPLICIT_CONFIRMATION_REQUIRED');
  // Only production default port is allowed in the shipped browser acceptance.
  if (port !== LOCAL_WSO2_PORT)
    throw new Error('LOCAL_WSO2_TLS_PIN_UNEXPECTED_PORT');
  return new Promise((resolve,reject)=>{
    // rejectUnauthorized:false is LIMITED to this single loopback certificate
    // retrieval. The resulting public-key hash is used in Chromium, which keeps
    // verification enabled for every other certificate.
    const socket=tlsConnect({host:'127.0.0.1',port,servername:'localhost',rejectUnauthorized:false});
    let settled=false;
    function finish(err,value){
      if(settled)return;settled=true;
      socket.destroy();
      if(err)reject(err);else resolve(value);
    }
    socket.setTimeout(timeoutMs,()=>finish(new Error('LOCAL_WSO2_TLS_CERTIFICATE_TIMEOUT')));
    socket.once('error',()=>finish(new Error('LOCAL_WSO2_TLS_ENDPOINT_UNAVAILABLE')));
    socket.once('secureConnect',()=>{
      try {
        const peer=socket.getPeerCertificate(true);
        finish(null,verifyLocalWso2Certificate(peer?.raw));
      } catch(e) {finish(e);}
    });
  });
}

export function chromiumPinnedTlsArgs(pinInfo) {
  if (pinInfo?.peer !== 'localhost:9444' ||
      typeof pinInfo.pin !== 'string' ||
      !/^[A-Za-z0-9+/]{43}=$/.test(pinInfo.pin))
    throw new Error('INVALID_LOCAL_WSO2_TLS_SPKI_PIN');
  return [`--ignore-certificate-errors-spki-list=${pinInfo.pin}`];
}
