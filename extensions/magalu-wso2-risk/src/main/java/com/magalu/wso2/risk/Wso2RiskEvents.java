package com.magalu.wso2.risk;

import org.wso2.carbon.identity.event.handler.AbstractEventHandler;
import org.wso2.carbon.identity.event.event.Event;
import org.wso2.carbon.identity.event.IdentityEventException;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;

import javax.servlet.http.HttpServletRequest;
import java.util.Map;

/** Event collection is telemetry only; never assume post-failure events enforce the current login.
 * Candidate event property contract requires runtime 7.3 verification before activation.
 */
public final class Wso2RiskEvents extends AbstractEventHandler {
    @FunctionalInterface public interface Collector {
        void collect(String tenant,String account,String rawIp,String agent,Signal.Outcome outcome);
    }
    private final Collector collector;
    private final TrustedClientIp network;
    public Wso2RiskEvents(TrustedClientIp network, Collector collector) {this.network=network;this.collector=collector;}
    @Override public String getName() {return "magaluRiskEventHandler";}
    @Override public void handleEvent(Event event) throws IdentityEventException {
        String kind=event.getEventName();
        Signal.Outcome outcome="AUTHENTICATION_STEP_FAILURE".equals(kind)?Signal.Outcome.FAILURE:
                "AUTHENTICATION_SUCCESS".equals(kind)?Signal.Outcome.SUCCESS:null;
        if(outcome==null)return;
        Map<String,Object> values=event.getEventProperties();
        // Strictly require a server-originating context, never trust an external header in the map.
        Object maybe=values.get("context");
        if(!(maybe instanceof AuthenticationContext))maybe=values.get("authenticationContext");
        if(!(maybe instanceof AuthenticationContext))return;
        AuthenticationContext context=(AuthenticationContext)maybe;
        HttpServletRequest req=Wso2RiskComponent.request(context);
        if(req==null)return;
        String user=values.get("userName") instanceof String?(String)values.get("userName"):null;
        if(user==null)return;
        String agent=req.getHeader("User-Agent");
        if(agent!=null && agent.length()>256)agent=null;
        // Current property may be absent in GA: verify actual event payload before release.
        String ip=network.resolve(req.getRemoteAddr(),req.getHeader("X-Forwarded-For"));
        if(ip!=null)collector.collect(context.getTenantDomain(),user,ip,agent,outcome);
    }
}
