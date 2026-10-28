import { randomBytes } from 'node:crypto';

const opaque = (bytes = 32) => randomBytes(bytes).toString('base64url');

/** Single-process, demonstration-only sessions. Use an HA-capable shared store on EKS. */
export class DemoSessionStore {
  constructor({ maxSessions = 500, ttlMs = 60 * 60_000, secure = false, now = () => Date.now() } = {}) {
    if (!Number.isInteger(maxSessions) || maxSessions < 1) throw new Error('Invalid maxSessions');
    this.sessions = new Map(); this.maxSessions = maxSessions; this.ttlMs = ttlMs; this.secure = secure; this.now = now;
    this.cookieName = secure ? '__Host-poc_sid' : 'poc_sid';
  }
  parseCookie(req) {
    const cookie = req.headers.cookie || '';
    // Duplicate session cookies are ambiguous across paths/proxies; reject.
    const matches = cookie.split(';').map(v => v.trim()).filter(v => v.startsWith(`${this.cookieName}=`));
    if (matches.length !== 1) return null;
    const id = matches[0].slice(this.cookieName.length + 1);
    return /^[A-Za-z0-9_-]{40,128}$/.test(id) ? id : null;
  }
  setCookie(res, id, maxAge = 3600) {
    const value = `${this.cookieName}=${id}; HttpOnly; SameSite=Lax; Path=/; Max-Age=${maxAge}${this.secure ? '; Secure' : ''}`;
    res.setHeader('Set-Cookie', value);
  }
  clean() { for (const [id, s] of this.sessions) if (s.expires <= this.now()) this.sessions.delete(id); }
  ensure(req, res) {
    this.clean(); const current = this.parseCookie(req);
    let session = current && this.sessions.get(current);
    if (session) { session.expires = this.now() + this.ttlMs; this.setCookie(res, session.id); return session; }
    // Reject rather than evict an authenticated session for a new anonymous visitor.
    if (this.sessions.size >= this.maxSessions) return null;
    const id = opaque(); session = { id, csrf: opaque(24), created: this.now(), expires: this.now() + this.ttlMs, logins: {}, pending: {} };
    this.sessions.set(id, session); this.setCookie(res, id); return session;
  }
  rotate(session, res) {
    if (!this.sessions.has(session.id)) throw new Error('Unknown session');
    this.sessions.delete(session.id);
    session.id = opaque(); session.csrf = opaque(24); session.expires = this.now() + this.ttlMs;
    this.sessions.set(session.id, session); this.setCookie(res, session.id);
    return session;
  }
  destroy(session, res) {
    this.sessions.delete(session.id);
    this.setCookie(res, '', 0);
  }
}
