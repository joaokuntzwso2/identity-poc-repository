/** RFP B-01/B-02: a successful identifier predicate still does NOT prove the
 * four authentications belong to the same canonical human being. */
export function evaluatePairwise(entries) {
  const required = ['aurora-web', 'aurora-app', 'brisa-web', 'brisa-app'];
  const present = required.filter(key => Boolean(entries[key]?.verified && entries[key]?.claims?.sub && entries[key]?.claims?.iss));
  if (present.length !== 4) return { status: 'INCOMPLETE', present, missing: required.filter(k => !present.includes(k)), predicate: null, canonicalPerson: 'NOT_VERIFIED' };
  const id = key => entries[key].claims.sub;
  const iss = key => entries[key].claims.iss;
  const checks = {
    auroraSameSector: id('aurora-web') === id('aurora-app'),
    brisaSameSector: id('brisa-web') === id('brisa-app'),
    crossBrandDifferent: id('aurora-web') !== id('brisa-web'),
    auroraSameIssuer: iss('aurora-web') === iss('aurora-app'),
    brisaSameIssuer: iss('brisa-web') === iss('brisa-app'),
    bothBrandsHaveIdenticalIssuer: iss('aurora-web') === iss('brisa-web'),
  };
  // Independent issuers across BRANDS are allowed. Within one brand the
  // same sub from unrelated issuers is not evidence of a shared sector.
  const predicate = checks.auroraSameSector && checks.brisaSameSector && checks.crossBrandDifferent && checks.auroraSameIssuer && checks.brisaSameIssuer;
  return { status: predicate ? 'IDENTIFIER_PREDICATE_MET' : 'FAIL', present, missing: [], predicate, checks, canonicalPerson: 'NOT_VERIFIED', acceptance: 'NOT_VERIFIED' };
}
