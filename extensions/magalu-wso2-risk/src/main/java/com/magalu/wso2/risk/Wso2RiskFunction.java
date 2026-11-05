package com.magalu.wso2.risk;

import org.wso2.carbon.identity.application.authentication.framework.config.model.graph.js.JsAuthenticationContext;

@FunctionalInterface
public interface Wso2RiskFunction {
    String magaluRiskCheck(JsAuthenticationContext context, String verifiedUsername);
}
