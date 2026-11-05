"""Exact, journal-owned WSO2 GA 7.3 conditional-authentication composer.

The existing P0.10-derivative scripts are the authority. Neither script is
replaced by an Aurora-only template. Every source script is SHA-256 pinned to
live readback evidence from the v10 runtime (2026-11-05). Any drift REFUSES.

Risk gating is after successful Basic and before completion. This is NOT a
pre-credential admission control and a DELAY decision is currently rejected,
not delayed. Do not claim full Magalu acceptance without the remaining gates.
"""
import copy
import hashlib
import json
from pathlib import Path

DISPLAY_NAMES = {
    ('aurora.identity.test', 'aurora-web'): 'Identity Lab v10 Aurora Web',
    ('aurora.identity.test', 'aurora-app'): 'Identity Lab v10 Aurora Mobile Browser Preview',
    ('brisa.identity.test', 'brisa-web'): 'Identity Lab v10 Brisa Web',
    ('brisa.identity.test', 'brisa-app'): 'Identity Lab v10 Brisa Mobile Browser Preview',
}

# Exact SHA-256 of the deployed live script STRING, not the legacy local P0.10.
APPROVED_LIVE_SCRIPT_SHA256 = {
    'aurora.identity.test': '45e5b2cad64872a2ecc6745f30a39b8ec00b8c548cb02af76f22824c61461e51',
    'brisa.identity.test': '1d55423223853a1d53400bd59834befe451ad7e5b506ae15f42d4d89e0177f2e',
}

# Only source statement replaced in either 2026-11-05 Graal graph-compatible
# script. Do not hoist context from onSuccess into the step-2 callback.
ORIGINAL_BRANCH = '            if (approvalRequested || attemptsRequireTotp) {'

GATED_BRANCH = '''            // BEGIN MAGALU_RISK_GATE_V2: after genuine Basic step 1 success.
            // Unavailable decisions fail closed, never ALLOW by default.
            var magaluSubject = context.steps[1] && context.steps[1].subject;
            var magaluDecision = magaluSubject && magaluSubject.username ?
                magaluRiskCheck(context, String(magaluSubject.username)) : 'DENY';
            if (magaluDecision !== 'ALLOW' && magaluDecision !== 'DELAY' &&
                    magaluDecision !== 'CHALLENGE' && magaluDecision !== 'STEP_UP' &&
                    magaluDecision !== 'DENY') {
                magaluDecision = 'DENY';
            }
            // DELAY currently rejects without issuing a token; it is NOT a true
            // delayed admission implementation and cannot pass DELAY acceptance.
            if (magaluDecision === 'DENY' || magaluDecision === 'DELAY') {
                fail({errorCode:'access_denied',
                      errorMessage:'Authentication could not be completed'});
                return;
            }
            var magaluRequiresTotp = magaluDecision === 'CHALLENGE' ||
                magaluDecision === 'STEP_UP';
            // END MAGALU_RISK_GATE_V2. The existing onSuccess step-2 callback
            // independently checks requestedAcr; NEVER auto-assert ACR here.
            if (approvalRequested || attemptsRequireTotp || magaluRequiresTotp) {'''

class UnsafeSequence(RuntimeError):
    pass


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False)


def fingerprint(value):
    return hashlib.sha256(canonical(value).encode()).hexdigest()


def compose(tenant, name, app, _legacy_unused_brisa_script=None):
    """Return a staged *sequence only*, with no API writes or app recreation."""
    key = (tenant, name)
    if key not in DISPLAY_NAMES or not isinstance(app, dict):
        raise UnsafeSequence('tenant/channel not allowlisted')
    if app.get('name') != DISPLAY_NAMES[key] or not isinstance(app.get('id'), str):
        raise UnsafeSequence('live/journal application identity drift')
    seq = app.get('authenticationSequence')
    if not isinstance(seq, dict) or seq.get('type') != 'USER_DEFINED':
        raise UnsafeSequence('expected existing USER_DEFINED live sequence')
    steps = seq.get('steps')
    if not isinstance(steps, list) or len(steps) != 2:
        raise UnsafeSequence('existing two-step Basic+TOTP required')
    for index, authenticators in ((0, {'BasicAuthenticator', 'basic'}), (1, {'totp'})):
        step = steps[index]
        if not isinstance(step, dict) or step.get('id') != index + 1:
            raise UnsafeSequence('existing auth step ordering drift')
        opts = step.get('options')
        if (not isinstance(opts, list) or len(opts) != 1 or
                not isinstance(opts[0], dict) or opts[0].get('idp') != 'LOCAL' or
                opts[0].get('authenticator') not in authenticators):
            raise UnsafeSequence('existing Basic/TOTP authenticator drift')
    script = seq.get('script')
    if not isinstance(script, str):
        raise UnsafeSequence('missing live authentication script')
    if hashlib.sha256(script.encode('utf-8')).hexdigest() != APPROVED_LIVE_SCRIPT_SHA256[tenant]:
        raise UnsafeSequence('unreviewed live adaptive script SHA-256; refuse overwrite')
    if script.count(ORIGINAL_BRANCH) != 1:
        raise UnsafeSequence('Graal step-1 branch absent or ambiguous')
    if 'MAGALU_RISK_GATE_V2' in script or 'magaluRiskCheck' in script:
        raise UnsafeSequence('existing risk function / uncertain previous patch')
    # The original step-2 onSuccess (including the Aurora approval ACR selection,
    # and both tenants' failed-login-claim reset) is left byte-for-byte intact.
    out = copy.deepcopy(seq)
    out['script'] = script.replace(ORIGINAL_BRANCH, GATED_BRANCH, 1)
    if out['steps'] != steps:
        raise UnsafeSequence('authenticator steps modified unexpectedly')
    return out


def read_brisa_script(root):
    """Legacy bootstrap interface; never use as source for the live Brisa flow."""
    return (Path(root) / 'scripts' / 'magalu-risk-flow.js').read_text()
