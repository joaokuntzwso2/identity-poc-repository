package com.magalu.wso2.risk;

import java.util.ArrayList;
import java.util.List;

/** Bounded test/single-node fallback. NOT suitable as multi-node source of truth. */
public final class InMemoryStore implements Store {
    private final List<Signal> entries = new ArrayList<>();
    private final int cap;
    public InMemoryStore(int cap) { if(cap<128)throw new IllegalArgumentException(); this.cap=cap; }
    @Override public synchronized List<Signal> recent(Policy p,long now) {
        List<Signal> list = new ArrayList<>();
        for (Signal s:entries) if (s.tenant.equals(p.tenant) && s.epochMillis>=now-p.windowSeconds*1000L && s.epochMillis<=now) list.add(s);
        return list.subList(Math.max(0,list.size()-p.maxEvents),list.size());
    }
    @Override public synchronized List<Signal> baseline(Policy p,String account,long now) {
        List<Signal> list = new ArrayList<>();
        for (Signal s:entries) if (s.tenant.equals(p.tenant) && account!=null && account.equals(s.account)
                && s.outcome==Signal.Outcome.SUCCESS && s.epochMillis>=now-p.baselineDays*86400000L) list.add(s);
        return List.copyOf(list.subList(Math.max(0,list.size()-512),list.size()));
    }
    @Override public synchronized void record(Signal s) {
        if (entries.size()==cap) entries.remove(0);
        entries.add(s);
    }
}
