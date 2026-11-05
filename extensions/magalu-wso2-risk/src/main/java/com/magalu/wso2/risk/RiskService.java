package com.magalu.wso2.risk;

import java.util.List;
import java.util.Map;

/** Pure decision facade; evaluator and store exceptions never become ALLOW. */
public final class RiskService {
    private final Store store;
    private final Map<String,Policy> policies;
    private final Engine engine = new Engine();
    private final EventSink sink;
    public RiskService(Store store, Map<String,Policy> policies, EventSink sink) {
        this.store=store; this.policies=Map.copyOf(policies); this.sink=sink;
    }
    public Decision check(Signal s) {
        Policy p=policies.get(s.tenant);
        if(p==null) return new Decision(Decision.Action.DENY,100,"UNKNOWN_TENANT","unknown");
        try {
            List<Signal> recent=store.recent(p,s.epochMillis);
            List<Signal> baseline=store.baseline(p,s.account,s.epochMillis);
            Decision d=engine.evaluate(p,s,recent,baseline);
            store.record(s);
            if(d.action!=Decision.Action.ALLOW) sink.submit(s,d);
            return d;
        } catch (Exception ex) {
            Decision d=new Decision(Decision.Action.DENY,100,"RISK_STATE_UNAVAILABLE",p.version);
            sink.submit(s,d);
            return d;
        }
    }
}
