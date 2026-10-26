import { loadPrivateWso2Clients } from './wso2-private.js';
/** Four independent client registrations. Values must be supplied by a real WSO2 deployment. */
export const brands = Object.freeze({
  aurora: { name: 'Aurora', color: '#EF6B53', sectorKey: 'aurora' },
  brisa: { name: 'Brisa', color: '#5B6EEA', sectorKey: 'brisa' },
});

const environmentClients = Object.freeze(Object.fromEntries(
  Object.keys(brands).flatMap(brand => ['web', 'app'].map(channel => {
    const name = `${brand}-${channel}`;
    const envKey = name.toUpperCase().replace(/-/g, '_');
    return [name, {
      name, brand, channel,
      clientId: process.env[`OIDC_${envKey}_CLIENT_ID`] || '',
      issuer: process.env[`OIDC_${envKey}_ISSUER`] || process.env.OIDC_ISSUER || '',
      clientSecret: process.env[`OIDC_${envKey}_CLIENT_SECRET`] || '',
      scope: 'openid',
    }];
  }))
));

export const clients = Object.freeze(loadPrivateWso2Clients({ fallback: environmentClients }));
export const appConfig = Object.freeze({
  origin: process.env.PUBLIC_ORIGIN || 'http://localhost:4000',
  port: Number(process.env.PORT || 4000),
  environment: process.env.NODE_ENV || 'development',
  allowInsecureLocal: process.env.ALLOW_INSECURE_LOCAL === 'true',
  adminAllowlist: (process.env.OPERATOR_ALLOWLIST || '').split(',').map(s => s.trim()).filter(Boolean),
  sectorBaseUrl: process.env.SECTOR_BASE_URL || '',
  maxSessions: Number(process.env.MAX_SESSIONS || 500),
});

export function configuredClients() {
  return Object.values(clients).filter(c => Boolean(c.clientId && c.issuer));
}
