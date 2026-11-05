package com.magalu.wso2.risk;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/** Multivariate detection. No single failed-login counter is sufficient for distributed spray. */
public final class Engine {
    public Decision evaluate(Policy policy, Signal candidate, List<Signal> window, List<Signal> baseline) {
        if (!policy.tenant.equals(candidate.tenant)) throw new SecurityException("tenant mismatch");
        long since = candidate.epochMillis - policy.windowSeconds * 1000L;
        List<Signal> hits = new ArrayList<>();
        for (Signal s : window) {
            if (!candidate.tenant.equals(s.tenant) || s.epochMillis < since || s.epochMillis > candidate.epochMillis) continue;
            hits.add(s);
        }
        hits.add(candidate);
        int accountSourceFailures = 0, sourceFailures = 0, accountFailures = 0;
        Set<String> networkAccounts = new HashSet<>(), networkIps = new HashSet<>();
        Set<String> campaignAccounts = new HashSet<>(), campaignIps = new HashSet<>();
        List<Long> cadence = new ArrayList<>();
        List<Long> agentCadence = new ArrayList<>();
        Set<String> agentAccounts = new HashSet<>(), agentIps = new HashSet<>();
        int campaignFailures = 0, agentFailures = 0;
        for (Signal s : hits) {
            boolean fail = s.outcome == Signal.Outcome.FAILURE;
            if (fail && eq(candidate.account, s.account)) accountFailures++;
            if (fail && eq(candidate.account,s.account) && eq(candidate.ip,s.ip)) accountSourceFailures++;
            if (fail && eq(candidate.network,s.network)) {
                sourceFailures++; if (s.account != null) networkAccounts.add(s.account);
                if (s.ip != null) networkIps.add(s.ip);
            }
            // A campaign needs an independent device OR user-agent signature, not IP rotation alone.
            boolean sameAgent = candidate.agent != null && candidate.agent.equals(s.agent);
            boolean verifiedSession = candidate.session != null && candidate.session.equals(s.session);
            boolean deviceAndAgent = candidate.device != null && candidate.device.equals(s.device) && sameAgent;
            // Server-issued session continuity is stronger than a raw client fingerprint.
            // User-Agent alone is never sufficient: require regular timing AND multi-IP/account failures.
            boolean correlated = deviceAndAgent || (verifiedSession && sameAgent);
            if(sameAgent) {
                agentCadence.add(s.epochMillis);
                if(fail) {
                    agentFailures++;
                    if(s.account != null) agentAccounts.add(s.account);
                    if(s.ip != null) agentIps.add(s.ip);
                }
            }
            if (correlated && fail) {
                campaignFailures++;
                if (s.account != null) campaignAccounts.add(s.account);
                if (s.ip != null) campaignIps.add(s.ip);
            }
            // A server-verifiable device signal is unavailable by default; cadence alone is weak.
            if (correlated) cadence.add(s.epochMillis);
        }
        int score = 0;
        String reason = "NORMAL";
        if (accountSourceFailures >= 6) { score = 92; reason = "SINGLE_SOURCE_BRUTE_FORCE"; }
        else if (accountSourceFailures >= 4) { score = 63; reason = "SINGLE_SOURCE_VELOCITY"; }
        else if (accountSourceFailures >= 3) { score = 38; reason = "SINGLE_SOURCE_EARLY_WARNING"; }
        else if (accountSourceFailures >= 2) { score = 25; reason = "SINGLE_SOURCE_EARLY_WARNING"; }
        // Network spray: many distinct accounts are mandatory, not one account's failure count.
        if (networkAccounts.size() >= 8 && sourceFailures >= 8 && score < 95) {
            score = 95; reason = "NETWORK_MULTI_ACCOUNT_SPRAY";
        } else if (networkAccounts.size() >= 5 && sourceFailures >= 5 && score < 76) {
            score = 76; reason = "NETWORK_SPRAY";
        }
        // Cross-network campaign: distinct accounts + distinct IPs + shared non-IP signature.
        if (campaignAccounts.size() >= 8 && campaignIps.size() >= 4 && campaignFailures >= 8 && score < 98) {
            score = 98; reason = "CORRELATED_DISTRIBUTED_STUFFING";
        } else if (campaignAccounts.size() >= 5 && campaignIps.size() >= 3 && campaignFailures >= 5 && score < 80) {
            score = 80; reason = "CORRELATED_CAMPAIGN";
        }
        if (candidate.automation && score < 56) { score = 56; reason = "AUTOMATION_SIGNAL"; }
        if (candidate.challengeFailed && score < 92) { score = 92; reason = "CHALLENGE_FAILURE"; }
        // Cross-account regular timing with a reused fingerprint, not simply a request count.
        boolean agentRegular = agentCadence.size() >= 6 && regularCadence(agentCadence);
        if (agentRegular && agentAccounts.size() >= 8 && agentIps.size() >= 4
                && agentFailures >= 8 && score < 96) {
            score = 96; reason = "MULTI_IP_AGENT_CADENCE_SPRAY";
        } else if ((cadence.size() >= 6 && regularCadence(cadence))
                || (agentRegular && agentAccounts.size() >= 4 && agentFailures >= 4)) {
            if(score < 78) {score = 78; reason = "BOT_CADENCE_AND_REUSE";}
        }
        // Account-specific baseline: only successful prior sessions, from >=2 separate days.
        Set<Long> days = new HashSet<>();
        Set<String> oldDevices = new HashSet<>(), oldNetworks = new HashSet<>();
        Set<String> successSessions = new HashSet<>();
        for (Signal old : baseline) {
            if (!candidate.tenant.equals(old.tenant) || !eq(candidate.account,old.account)
                    || old.outcome != Signal.Outcome.SUCCESS || old.epochMillis >= candidate.epochMillis) continue;
            if (old.session != null) successSessions.add(old.session);
            days.add(Math.floorDiv(old.epochMillis, 86400000L));
            if (old.device != null) oldDevices.add(old.device);
            if (old.network != null) oldNetworks.add(old.network);
        }
        if (successSessions.size() >= policy.minBaselineSuccesses && days.size() >= 2
                && candidate.device != null && candidate.network != null
                && !oldDevices.isEmpty() && !oldNetworks.isEmpty()
                && !oldDevices.contains(candidate.device) && !oldNetworks.contains(candidate.network)
                && score < 77) { score = 77; reason = "ACCOUNT_BASELINE_DEVIATION"; }
        Decision.Action action = score >= policy.deny ? Decision.Action.DENY
                : score >= policy.stepUp ? Decision.Action.STEP_UP
                : score >= policy.challenge ? Decision.Action.CHALLENGE
                : score >= policy.delay ? Decision.Action.DELAY : Decision.Action.ALLOW;
        return new Decision(action, score, reason, policy.version);
    }

    private static boolean eq(String a, String b) { return a != null && a.equals(b); }
    private static boolean regularCadence(List<Long> times) {
        times.sort(Long::compareTo);
        long first = times.get(1) - times.get(0);
        if (first < 40 || first > 1500) return false;
        for (int i=2; i<times.size(); i++) {
            long d = times.get(i)-times.get(i-1);
            if (Math.abs(d-first) > 90) return false;
        }
        return true;
    }
}
