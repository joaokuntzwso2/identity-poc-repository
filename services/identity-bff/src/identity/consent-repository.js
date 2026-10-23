import {createHash, randomUUID} from 'node:crypto';

const allowedBrands = new Set(['aurora','brisa']);
const allowedDecisions = new Set(['GRANTED','REVOKED']);
const dimensions = ['subjectKey','issuer','brand','clientKey','targetBrand','purpose','scope'];
const clean = (s,limit=100) => typeof s==='string' && s.length>0 && s.length<=limit && /^[a-zA-Z0-9_.:\/-]+$/.test(s);
export function consentKey({issuer,subject}) {
  if (!issuer || !subject) throw new Error('missing_validated_principal');
  return createHash('sha256').update(`${issuer}\u0000${subject}`).digest('hex');
}
export function validateConsentInput(d) {
  if (!d || !allowedBrands.has(d.brand) || !allowedBrands.has(d.targetBrand) || d.brand===d.targetBrand ||
      !clean(d.clientKey,100) || !clean(d.purpose) || !clean(d.scope,150) || !clean(d.issuer,512) ||
      !/^[0-9a-f]{64}$/.test(d.subjectKey)) throw new Error('invalid_consent_dimensions');
  return d;
}
export class DurableConsentRepository {
  constructor(pool) {this.pool=pool;}
  async record(input) {
    const d=validateConsentInput(input);
    if (!allowedDecisions.has(d.decision)) throw new Error('invalid_consent_action');
    const cx=await this.pool.connect();
    const key=dimensions.map(k=>d[k]);
    try {
      await cx.query('BEGIN');
      await cx.query(`INSERT INTO identity_poc.consent_state
        (subject_key,issuer,brand,client_key,target_brand,purpose,scope)
        VALUES($1,$2,$3,$4,$5,$6,$7) ON CONFLICT DO NOTHING`,key);
      const r=await cx.query(`SELECT revision FROM identity_poc.consent_state WHERE
        subject_key=$1 AND issuer=$2 AND brand=$3 AND client_key=$4 AND target_brand=$5 AND purpose=$6 AND scope=$7 FOR UPDATE`,key);
      if(r.rows.length!==1)throw new Error('consent_state_missing');
      const revision=Number(r.rows[0].revision)+1;
      const eventId=randomUUID();
      await cx.query(`INSERT INTO identity_poc.consent_events
        (event_id,subject_key,issuer,brand,client_key,target_brand,purpose,scope,revision,decision)
        VALUES($8,$1,$2,$3,$4,$5,$6,$7,$9,$10)`, [...key,eventId,revision,d.decision]);
      await cx.query(`UPDATE identity_poc.consent_state SET revision=$8,decision=$9,changed_at=now() WHERE
        subject_key=$1 AND issuer=$2 AND brand=$3 AND client_key=$4 AND target_brand=$5 AND purpose=$6 AND scope=$7`, [...key,revision,d.decision]);
      await cx.query('COMMIT');
      return {eventId,revision,decision:d.decision,mode:'AE_POSTGRES_LEDGER'};
    } catch(e){await cx.query('ROLLBACK').catch(()=>{});throw e;}
    finally{cx.release();}
  }
  async evaluate(input) {
    const d=validateConsentInput(input);
    const key=dimensions.map(k=>d[k]);
    const r=await this.pool.query(`SELECT decision,revision FROM identity_poc.consent_state WHERE
      subject_key=$1 AND issuer=$2 AND brand=$3 AND client_key=$4 AND target_brand=$5 AND purpose=$6 AND scope=$7`,key);
    return {decision:r.rows[0]?.decision==='GRANTED'?'ALLOW':'DENY',revision:Number(r.rows[0]?.revision||0),mode:'AE_POSTGRES_LEDGER'};
  }
}
