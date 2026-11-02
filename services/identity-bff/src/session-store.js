import { randomBytes } from 'node:crypto';
const opaque=(bytes=32)=>randomBytes(bytes).toString('base64url');
/** Bounded single-process session store for the local lab. Not an HA store. */
export class DemoSessionStore {
  constructor({maxSessions=500,ttlMs=60*60_000,idleMs=ttlMs,absoluteMs=8*60*60_000,
    secure=false,now=()=>Date.now()}={}) {
    for(const x of [maxSessions,ttlMs,idleMs,absoluteMs]) if(!Number.isSafeInteger(x)||x<1)
      throw new Error('Invalid session bounds');
    if(absoluteMs<idleMs) throw new Error('Session absolute lifetime shorter than idle lifetime');
    this.sessions=new Map();this.maxSessions=maxSessions;this.idleMs=idleMs;
    this.absoluteMs=absoluteMs;this.secure=secure;this.now=now;
    this.cookieName=secure?'__Host-poc_sid':'poc_sid';
  }
  parseCookie(req) {
    const cookie=req.headers.cookie||'';
    const matches=cookie.split(';').map(x=>x.trim()).filter(x=>x.startsWith(`${this.cookieName}=`));
    if(matches.length!==1)return null;
    const id=matches[0].slice(this.cookieName.length+1);
    return /^[A-Za-z0-9_-]{40,128}$/.test(id)?id:null;
  }
  setCookie(res,id,maxAge=3600){
    const attrs=`${this.cookieName}=${id}; HttpOnly; SameSite=Lax; Path=/; Max-Age=${Math.max(0,Math.floor(maxAge))}${this.secure?'; Secure':''}`;
    res.setHeader('Set-Cookie',attrs);
  }
  deadline(s){return Math.min(s.expires,s.created+this.absoluteMs);}
  valid(s){return Boolean(s && this.deadline(s)>this.now());}
  clean(){for(const [id,s] of this.sessions)if(!this.valid(s))this.sessions.delete(id);}
  ensure(req,res){
    this.clean();const current=this.parseCookie(req);
    let session=current && this.sessions.get(current);
    if(session && this.valid(session)) {
      session.expires=this.now()+this.idleMs;
      this.setCookie(res,session.id,(this.deadline(session)-this.now())/1000);
      return session;
    }
    if(this.sessions.size>=this.maxSessions)return null;
    const id=opaque();session={id,csrf:opaque(24),created:this.now(),
      expires:this.now()+this.idleMs,logins:Object.create(null),pending:Object.create(null)};
    this.sessions.set(id,session);
    this.setCookie(res,id,(this.deadline(session)-this.now())/1000);
    return session;
  }
  rotate(session,res){
    if(!this.sessions.has(session.id)||!this.valid(session))throw new Error('Unknown or expired session');
    const oldId=session.id;this.sessions.delete(oldId);
    session.id=opaque();session.csrf=opaque(24);
    session.expires=this.now()+this.idleMs;
    // Other pending authentication/step-up operations were bound to the old ID.
    session.pending=Object.create(null);
    this.sessions.set(session.id,session);
    this.setCookie(res,session.id,(this.deadline(session)-this.now())/1000);
    return session;
  }
  destroy(session,res){
    if(session?.id)this.sessions.delete(session.id);
    if(session){session.logins=Object.create(null);session.pending=Object.create(null);session.csrf='';}
    this.setCookie(res,'',0);
  }
}
