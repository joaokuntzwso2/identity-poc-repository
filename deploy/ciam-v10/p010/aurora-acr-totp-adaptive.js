/*
 * CIAM v10 P0.10 WSO2 adaptive authentication.
 * This script is installed ONLY on Aurora Web and Aurora Mobile Browser.
 * ACR is selected ONLY after a successful genuine WSO2 TOTP step.
 * Identity server owns TOTP enrollment, verification and auth_time/AMR issuance.
 */
var CIAM_APPROVAL_ACR = 'urn:ciampoc:assurance:totp:v1';
var onLoginRequest = function(context) {
    var requested = context.requestedAcr || [];
    var needApprovalMfa = false;
    for (var i = 0; i < requested.length; i++) {
        if (requested[i] === CIAM_APPROVAL_ACR) {
            needApprovalMfa = true;
        }
    }
    if (!needApprovalMfa) {
        executeStep(1);
        return;
    }
    executeStep(1, {
        onSuccess: function(context) {
            executeStep(2, {
                onSuccess: function(context) {
                    context.selectedAcr = CIAM_APPROVAL_ACR;
                }
            });
        }
    });
};
