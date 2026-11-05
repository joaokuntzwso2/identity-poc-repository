package com.magalu.wso2.risk;

public final class Decision {
    public enum Action { ALLOW, DELAY, CHALLENGE, STEP_UP, DENY }
    public final Action action;
    public final int score;
    public final String reason, policyVersion;
    public Decision(Action action, int score, String reason, String policyVersion) {
        this.action = action; this.score = score; this.reason = reason; this.policyVersion = policyVersion;
    }
    @Override public String toString() { return action + ":" + score + ":" + reason; }
}
