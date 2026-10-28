/** Isolated live-wso2 HTTP harness: disposable test-only manifest, no real WSO2/DB writes. */
import { spawn } from 'node:child_process';
import { createServer } from 'node:net';
import { cp, mkdir, mkdtemp, rm, writeFile, chmod, realpath } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

const REPO = fileURLToPath(new URL('../../../../', import.meta.url));
const delay = ms => new Promise(resolve => setTimeout(resolve, ms));
async function freePort() {
  const server = createServer();
  await new Promise((resolve, reject) => server.once('error', reject).listen(0, '127.0.0.1', resolve));
  const port = server.address().port;
  await new Promise(resolve => server.close(resolve));
  return port;
}
function mockManifest(base, idpOrigin = 'https://127.0.0.1:65534') {
  const clients = {};
  for (const brand of ['aurora', 'brisa']) for (const channel of ['web', 'app']) {
    const key = `${brand}-${channel}`;
    clients[key] = {
      clientId: `${key}-offline-test-only`,
      clientSecret: `${key}-never-real-test-only`,
      issuer: `${idpOrigin}/t/${brand}.identity.test/oauth2/token`,
      tenantDomain: `${brand}.identity.test`,
      redirectUri: `${base}/auth/${key}/callback`
    };
  }
  return { clients };
}
export async function startIsolatedLiveBff(t, { idpOrigin, caCert } = {}) {
  // macOS can expose the same temp dir as /var/... and /private/var/... .
  // Pin a canonical project root BEFORE writing the private manifest and copying
  // the runtime: strict wso2-private.js path checks must remain unchanged.
  const root = await realpath(await mkdtemp(join(tmpdir(), 'ciam-v10-bff-test-')));
  let child;
  let stopped = false;
  async function cleanup() {
    if (stopped) return;
    stopped = true;
    if (child && child.exitCode === null && child.signalCode === null) {
      child.kill('SIGTERM');
      await Promise.race([new Promise(resolve => child.once('exit', resolve)), delay(1000)]);
      if (child.exitCode === null && child.signalCode === null) child.kill('SIGKILL');
    }
    await rm(root, { recursive: true, force: true });
  }
  if (typeof t?.after === 'function') t.after(cleanup);
  try {
    await mkdir(join(root, 'services/identity-bff'), { recursive: true });
    await cp(join(REPO, 'services/identity-bff/src'), join(root, 'services/identity-bff/src'), { recursive: true });
    await cp(join(REPO, 'services/identity-bff/package.json'), join(root, 'services/identity-bff/package.json'));
    await mkdir(join(root, 'var/wso2'), { recursive: true, mode: 0o700 });
    await mkdir(join(root, 'business'), { recursive: true, mode: 0o700 });
    const port = await freePort();
    const base = `http://127.0.0.1:${port}`;
    const manifest = join(root, 'var/wso2/offline-bff-test.private.json');
    await writeFile(manifest, JSON.stringify(mockManifest(base, idpOrigin)), { mode: 0o600, flag: 'wx' });
    await chmod(manifest, 0o600);
    // Deliberately do not inherit WSO2, OAuth, private-manifest or business-data environment.
    const env = {
      PATH: process.env.PATH || '', HOME: root,
      NODE_ENV: 'development', IDENTITY_MODE: 'live-wso2',
      PUBLIC_ORIGIN: base, PORT: String(port), BIND_HOST: '127.0.0.1',
      ALLOW_INSECURE_LOCAL: 'true',
      WSO2_BFF_PRIVATE_MANIFEST: manifest,
      CIAM_BUSINESS_DATA_DIR: join(root, 'business'),
      ...(caCert ? { NODE_EXTRA_CA_CERTS: caCert } : {}),
    };
    let output = '';
    child = spawn(process.execPath, [join(root, 'services/identity-bff/src/server.js')], {
      cwd: root, env, stdio: ['ignore', 'pipe', 'pipe']
    });
    const collect = chunk => { output = (output + chunk.toString('utf8')).slice(-4000); };
    child.stdout.on('data', collect);
    child.stderr.on('data', collect);
    const deadline = Date.now() + 8000;
    while (Date.now() < deadline && child.exitCode === null && child.signalCode === null) {
      try {
        const r = await fetch(`${base}/api/health`, { signal: AbortSignal.timeout(450) });
        if (r.status === 200) return { base, root, close: cleanup };
      } catch { /* booting */ }
      await delay(50);
    }
    throw Error(`ISOLATED_LIVE_BFF_NOT_STARTED: exit=${child.exitCode ?? child.signalCode ?? 'unknown'} details=${output.slice(-1000)}`);
  } catch (error) {
    await cleanup();
    throw error;
  }
}
