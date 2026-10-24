import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {dirname, join} from 'node:path';
import {fileURLToPath} from 'node:url';
import {runInNewContext} from 'node:vm';

const source = readFileSync(
  join(dirname(fileURLToPath(import.meta.url)),
       'tenant-brand-bootstrap.mjs'),
  'utf8'
);

const found = source.match(
  /^export async function bootstrapTenants\([\s\S]*?^\}/m
);
assert.ok(found, 'bootstrapTenants must remain exported');

const code = found[0].replace(
  'export async function', 'async function'
);

const owner = () => ({
  username: 'labtenantadmin',
  password: 'offline-fixture',
  firstname: 'Identity',
  lastname: 'Lab',
  email: 'lab-tenant-admin@example.invalid'
});

const owned = (brand, state = 'create-started') => ({
  domain: `${brand}.identity.test`,
  owned: true,
  state,
  owner: owner()
});

function scenario({
  remote = [],
  initial = {},
  badOwner = false,
  badEmail = false
} = {}) {
  const db = new Map(remote.map(b => [
    `${b}.identity.test`,
    {
      id: `tenant-${b}`,
      ownerId: `owner-${b}`,
      owner: owner()
    }
  ]));

  const journal = {
    tenants: structuredClone(initial),
    clients: {}
  };

  const writes = [];

  const ctx = {
    process: {env: {}},
    fetch: () => {
      throw Error('NETWORK_FORBIDDEN');
    },
    BRANDS: ['aurora', 'brisa'],
    ROOT_TENANT_LIST: '/api/server/v1/tenants',
    ID: /^[a-zA-Z0-9-]{5,128}$/,
    statePath: 'offline-fixture',

    requireLab: () => ({
      base: 'https://localhost:9443',
      domains: {
        aurora: 'aurora.identity.test',
        brisa: 'brisa.identity.test'
      }
    }),

    config: () => ({}),
    deploymentPlan: () => ({apps: []}),
    readState: () => journal,
    privateWrite: () => {},
    safeOwner: owner,
    remoteTenants: async () => new Set(db.keys()),

    jsonCall: async (
      _fetch, _base, path,
      {method = 'GET', auth, payload} = {}
    ) => {
      assert.equal(auth?.username, 'superadmin');

      writes.push({method, path});

      if (method === 'POST') {
        assert.equal(path, '/api/server/v1/tenants');

        const brand = payload.domain.split('.')[0];

        db.set(payload.domain, {
          id: `tenant-${brand}`,
          ownerId: `owner-${brand}`,
          owner: structuredClone(payload.owners[0])
        });

        return {status: 201, data: {}};
      }

      const m = path.match(
        /^\/api\/server\/v1\/tenants\/domain\/(.+)$/
      );

      if (m) {
        const domain = decodeURIComponent(m[1]);
        const t = db.get(domain);

        return {
          status: t ? 200 : 404,
          data: t ? {
            id: t.id,
            domain,
            lifecycleStatus: {activated: true}
          } : {}
        };
      }

      const t = [...db.values()].find(
        v => path.includes('/' + v.id + '/')
      );

      if (path.endsWith('/owners')) {
        return {
          status: 200,
          data: t ? [{
            id: t.ownerId,
            username: badOwner
              ? 'wrong-owner'
              : t.owner.username
          }] : []
        };
      }

      if (path.includes('/owners/')) {
        return {
          status: 200,
          data: t ? {
            ...t.owner,
            id: t.ownerId,
            ...(badEmail
              ? {email: 'wrong@example.invalid'}
              : {})
          } : {}
        };
      }

      throw Error('UNEXPECTED_API_' + path);
    }
  };

  const run = runInNewContext(
    `${code}\nbootstrapTenants`,
    ctx,
    {timeout: 2000}
  );

  return {
    journal,
    writes,
    run: (onlyTenants = true) => run({
      env: {
        WSO2_ADMIN_USER: 'superadmin',
        WSO2_ADMIN_PASSWORD: 'offline-only'
      },
      stateFile: 'offline-fixture',
      onlyTenants,
      emit: () => {}
    })
  };
}

test('first run creates both roots; rerun makes no duplicate POST', async () => {
  const x = scenario();
  await x.run();
  await x.run();

  assert.equal(
    x.writes.filter(w => w.method === 'POST').length,
    2
  );
  assert.equal(x.journal.tenants.aurora.state, 'created');
  assert.equal(x.journal.tenants.brisa.state, 'created');
});

test('unowned Aurora is never adopted', async () => {
  const x = scenario({remote: ['aurora']});

  await assert.rejects(
    x.run(),
    /TENANT_ALREADY_EXISTS_UNOWNED_aurora/
  );

  assert.equal(x.writes.length, 0);
});

test('prepared journal cannot adopt externally created tenant', async () => {
  const x = scenario({
    remote: ['aurora'],
    initial: {
      aurora: owned('aurora', 'prepared')
    }
  });

  await assert.rejects(
    x.run(),
    /TENANT_PREPARED_BUT_DOMAIN_EXISTS_aurora/
  );

  assert.equal(x.writes.length, 0);
});

test('owner identity mismatch blocks Brisa creation', async () => {
  const x = scenario({
    remote: ['aurora'],
    initial: {aurora: owned('aurora')},
    badOwner: true
  });

  await assert.rejects(
    x.run(),
    /ROOT_OWNER_MISMATCH_aurora/
  );

  assert.equal(
    x.writes.filter(w => w.method === 'POST').length,
    0
  );
});

test('owner profile mismatch blocks Brisa creation', async () => {
  const x = scenario({
    remote: ['aurora'],
    initial: {aurora: owned('aurora')},
    badEmail: true
  });

  await assert.rejects(
    x.run(),
    /ROOT_OWNER_DETAILS_MISMATCH_aurora/
  );

  assert.equal(
    x.writes.filter(w => w.method === 'POST').length,
    0
  );
});

test('legacy full bootstrap refuses unsafe Basic-auth OIDC writes', async () => {
  const x = scenario();

  await assert.rejects(
    x.run(false),
    /TENANT_OIDC_MANAGEMENT_OAUTH_NOT_CONFIGURED/
  );

  assert.equal(x.journal.tenants.brisa.state, 'created');

  assert.equal(
    x.writes.filter(w => w.method === 'POST').length,
    2
  );
});
