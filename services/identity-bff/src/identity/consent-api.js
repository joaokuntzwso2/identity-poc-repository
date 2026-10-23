import { readFileSync } from 'node:fs';
import { DurableConsentRepository, consentKey } from './consent-repository.js';
let repositoryPromise;
async function repository() {
  if (!process.env.IDENTITY_CONSENT_DATABASE_URL) return null;
  if (!repositoryPromise) repositoryPromise = (async () => {
    const { Pool } = await import('pg');
    const options = {
      connectionString: process.env.IDENTITY_CONSENT_DATABASE_URL, max: 5,
      connectionTimeoutMillis: 4000, statement_timeout: 5000
    };
    if (process.env.NODE_ENV === 'production') {
      if (!process.env.IDENTITY_PG_SSL_CA_FILE) throw new Error('IDENTITY_PG_SSL_CA_FILE required in production');
      options.ssl = { ca: readFileSync(process.env.IDENTITY_PG_SSL_CA_FILE, 'utf8'), rejectUnauthorized: true };
    }
    return new DurableConsentRepository(new Pool(options));
  })();
  return repositoryPromise;
}
export async function handleDurableConsent({ req, res, u, s, reply, requirePost, bodyJson, subjectOf, clients, repoOverride }) {
  if (!requirePost(req, res, s)) return;
  const repo = repoOverride || await repository();
  if (!repo) return reply(res, 503, { error: 'durable_consent_not_configured', classification: 'AE' });
  const input = await bodyJson(req);
  const client = clients[input.client];
  if (!client || client.brand !== input.origin) return reply(res, 403, { error: 'client_brand_mismatch' });
  // Critical: identity is obtained exclusively from a signed WSO2 ID token already validated by the BFF.
  const principal = subjectOf(s, input.client);
  if (!principal) return reply(res, 403, { error: 'origin_client_authentication_required' });
  const login = s.logins[input.client];
  const d = {
    issuer: login.claims.iss, subjectKey: consentKey({ issuer: login.claims.iss, subject: login.claims.sub }),
    brand: input.origin, targetBrand: input.target, clientKey: input.client, purpose: input.purpose, scope: input.scope
  };
  try {
    if (u.pathname === '/api/identity/consent/record') {
      const result = await repo.record({ ...d, decision: input.action });
      return reply(res, 201, result);
    }
    if (u.pathname === '/api/identity/consent/check') {
      const result = await repo.evaluate(d);
      return reply(res, result.decision === 'ALLOW' ? 200 : 403, result);
    }
    return reply(res, 404, { error: 'route_not_found' });
  } catch (e) {
    if (['invalid_consent_dimensions', 'invalid_consent_action'].includes(e.message)) return reply(res, 400, { error: e.message });
    throw e;
  }
}
