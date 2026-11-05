/* WSO2 IS GA 7.3, Graal graph-compatible conditional authentication.
 * Each executeStep callback is an independently executed graph node. Never
 * close over variables from an earlier callback (or from doLogin).
 * The approval ACR is asserted ONLY after successful TOTP authentication.
 */
var MAGALU_STEPUP_THRESHOLD = 3;
var MAGALU_APPROVAL_ENABLED = true;
var MAGALU_APPROVAL_ACR = 'urn:ciampoc:assurance:totp:v1';
var MAGALU_FAILED_CLAIM = 'http://wso2.org/claims/identity/failedLoginAttemptsBeforeSuccess';
var onLoginRequest = function(context) {
    doLogin(context);
};
var doLogin = function(context) {
    executeStep(1, {
        onSuccess: function(context) {
            // Graal graph callbacks must compute decisions from their OWN
            // context; a value captured in doLogin is not reliably available.
            var requested = context.requestedAcr || [];
            var approvalRequested = MAGALU_APPROVAL_ENABLED &&
                requested.indexOf(MAGALU_APPROVAL_ACR) !== -1;
            var subject = context.steps[1].subject;
            var raw = subject && subject.localClaims ?
                subject.localClaims[MAGALU_FAILED_CLAIM] : null;
            var failures = Number(raw);
            var attemptsRequireTotp = raw !== null && raw !== undefined &&
                raw !== '' && isFinite(failures) &&
                failures >= MAGALU_STEPUP_THRESHOLD;
            if (approvalRequested || attemptsRequireTotp) {
                executeStep(2, {
                    onSuccess: function(context) {
                        // Do not capture approvalRequested, attemptsRequireTotp
                        // or subject from the prior callback: they are not
                        // guaranteed to exist in the Graal callback graph.
                        var authenticated = context.steps[1].subject;
                        var claim = authenticated && authenticated.localClaims ?
                            authenticated.localClaims[MAGALU_FAILED_CLAIM] : null;
                        var count = Number(claim);
                        if (claim !== null && claim !== undefined && claim !== '' &&
                                isFinite(count) && count >= MAGALU_STEPUP_THRESHOLD) {
                            authenticated.localClaims[MAGALU_FAILED_CLAIM] = '0';
                        }
                        var acrs = context.requestedAcr || [];
                        if (MAGALU_APPROVAL_ENABLED &&
                                acrs.indexOf(MAGALU_APPROVAL_ACR) !== -1) {
                            context.selectedAcr = MAGALU_APPROVAL_ACR;
                        }
                    }
                });
            }
        },
        onFail: function(context) {
            // Retry only primary authentication. This must not bypass step 1.
            doLogin(context);
        }
    });
};
