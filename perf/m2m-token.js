/** k6: run ONLY in an authorized, isolated load environment. No mocked issuer responses. */
import http from 'k6/http';
import { check, sleep } from 'k6';
import { Rate, Trend, Counter } from 'k6/metrics';
import encoding from 'k6/encoding';
const tokenUrl = __ENV.TOKEN_ENDPOINT;
const clientId = __ENV.M2M_CLIENT_ID;
const secret = __ENV.M2M_CLIENT_SECRET;
if (!tokenUrl || !clientId || !secret || !tokenUrl.startsWith('https://')) throw Error('Provide valid HTTPS TOKEN_ENDPOINT and M2M_CLIENT_ID/M2M_CLIENT_SECRET');
const stage = __ENV.LOAD_STAGE || 'baseline';
const rate = Number(__ENV.RATE || (stage === 'peak' ? '1000' : '100'));
const duration = __ENV.DURATION || (stage === 'peak' ? '10m' : '3m');
if (!Number.isInteger(rate) || rate < 1 || rate > 2000) throw Error('Invalid RATE');
export const options = {
  insecureSkipTLSVerify: false,
  scenarios: { token_issuance: { executor: 'constant-arrival-rate', rate, timeUnit: '1s', duration, preAllocatedVUs: Number(__ENV.PREALLOCATED_VUS || 500), maxVUs: Number(__ENV.MAX_VUS || 2400) } },
  thresholds: { 'http_req_failed': ['rate<0.01'], 'token_latency': ['p(95)<1000', 'p(99)<1800'] },
  noConnectionReuse: false,
  discardResponseBodies: false,
};
const failures = new Rate('grant_failures');
const latency = new Trend('token_latency', true);
const grants = new Counter('issued_grants');
export default function () {
  const basic = encoding.b64encode(`${clientId}:${secret}`);
  const body = `grant_type=client_credentials&scope=${encodeURIComponent(__ENV.M2M_SCOPES || 'catalog.read')}`;
  const response = http.post(tokenUrl, body, { headers: { 'Authorization': `Basic ${basic}`, 'Content-Type': 'application/x-www-form-urlencoded', 'Accept': 'application/json' }, tags: { flow: 'client_credentials' }, timeout: '12s' });
  latency.add(response.timings.duration);
  const success = check(response, { 'HTTP 200': r => r.status === 200, 'OAuth token response': r => { if (r.status !== 200) return false; try { const d = JSON.parse(r.body); return Boolean(d.access_token && d.token_type); } catch { return false; } } });
  failures.add(!success); if (success) grants.add(1);
  // Never log token values, credentials, assertion contents, or user PII.
}
