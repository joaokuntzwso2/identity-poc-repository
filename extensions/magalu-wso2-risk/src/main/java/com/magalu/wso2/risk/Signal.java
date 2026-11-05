package com.magalu.wso2.risk;

/** Only HMAC pseudonyms, boolean outcomes and time. Null keys mean unavailable signals. */
public final class Signal {
    public enum Outcome { ATTEMPT, FAILURE, SUCCESS }
    public final String tenant, account, ip, network, device, session, agent;
    public final long epochMillis;
    public final Outcome outcome;
    public final boolean automation, challengeFailed;

    public Signal(String tenant, String account, String ip, String network, String device,
                  String session, String agent, long epochMillis, Outcome outcome,
                  boolean automation, boolean challengeFailed) {
        this.tenant = tenant; this.account = account; this.ip = ip; this.network = network;
        this.device = device; this.session = session; this.agent = agent;
        this.epochMillis = epochMillis; this.outcome = outcome;
        this.automation = automation; this.challengeFailed = challengeFailed;
    }
}
