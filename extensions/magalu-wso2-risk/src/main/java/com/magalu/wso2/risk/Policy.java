package com.magalu.wso2.risk;

import java.io.IOException;
import java.io.InputStream;
import java.util.Objects;
import java.util.Properties;

/** Immutable tenant policy. Higher score is more restrictive; no permanent account lock. */
public final class Policy {
    public final String tenant;
    public final int delay, challenge, stepUp, deny;
    public final int windowSeconds, maxEvents, baselineDays, minBaselineSuccesses;
    public final String version;

    public Policy(String tenant, int delay, int challenge, int stepUp, int deny,
                  int windowSeconds, int maxEvents, int baselineDays, int minBaselineSuccesses, String version) {
        this.tenant = Objects.requireNonNull(tenant);
        this.delay = delay; this.challenge = challenge; this.stepUp = stepUp; this.deny = deny;
        this.windowSeconds = windowSeconds; this.maxEvents = maxEvents;
        this.baselineDays = baselineDays; this.minBaselineSuccesses = minBaselineSuccesses;
        this.version = Objects.requireNonNull(version);
        if (!(0 < delay && delay < challenge && challenge < stepUp && stepUp < deny && deny <= 100)
                || windowSeconds < 60 || windowSeconds > 3600 || maxEvents < 128 || maxEvents > 8192
                || baselineDays < 1 || baselineDays > 90 || minBaselineSuccesses < 3) {
            throw new IllegalArgumentException("invalid risk policy");
        }
    }

    public static Policy load(InputStream input) throws IOException {
        Properties p = new Properties(); p.load(input);
        return new Policy(p.getProperty("tenant"), Integer.parseInt(p.getProperty("delay")),
                Integer.parseInt(p.getProperty("challenge")), Integer.parseInt(p.getProperty("step_up")),
                Integer.parseInt(p.getProperty("deny")), Integer.parseInt(p.getProperty("window_seconds")),
                Integer.parseInt(p.getProperty("max_events")), Integer.parseInt(p.getProperty("baseline_days")),
                Integer.parseInt(p.getProperty("min_baseline_successes")), p.getProperty("version"));
    }
}
