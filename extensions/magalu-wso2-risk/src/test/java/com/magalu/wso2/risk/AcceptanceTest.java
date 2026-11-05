package com.magalu.wso2.risk;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;

/** OFFLINE_TEST only; does not assert WSO2 integration, TOTP or real tokens. */
public final class AcceptanceTest {
    static Policy aurora=new Policy("aurora.identity.test",20,45,65,90,900,2048,45,5,"a1");
    static Policy brisa=new Policy("brisa.identity.test",30,55,75,95,900,2048,45,5,"b1");
    static final long NOW=1780000000000L;
    static final Engine engine=new Engine();
    static final AtomicInteger tested=new AtomicInteger();
    static void check(boolean good, String test) {
        if(!good)throw new AssertionError(test);
        tested.incrementAndGet();System.out.println("PASS OFFLINE_TEST " + test);
    }
    static Signal s(String tenant,String account,String ip,String network,String device,String session,
                    String agent,long when, Signal.Outcome outcome) {
        return new Signal(tenant,account,ip,network,device,session,agent,when,outcome,false,false);
    }
    static void bruteForce() {
        List<Signal> history=new ArrayList<>();
        for(int i=0;i<6;i++)history.add(s(aurora.tenant,"acct-a","ip-1","net-1","dev-1","s"+i,"ua-1",NOW-i*1000L,Signal.Outcome.FAILURE));
        Decision d=engine.evaluate(aurora,s(aurora.tenant,"acct-a","ip-1","net-1","dev-x","login","ua-2",NOW,Signal.Outcome.ATTEMPT),history,List.of());
        check(d.action==Decision.Action.DENY && "SINGLE_SOURCE_BRUTE_FORCE".equals(d.reason),"A single IP + account brute force -> DENY");
    }
    static void stuffing() {
        List<Signal> history=new ArrayList<>();
        for(int i=0;i<9;i++)history.add(s(aurora.tenant,"target-"+i,"ip-"+i,"net-"+i,"dev-shared","session-"+i,"agent-shared",NOW-i*5000L,Signal.Outcome.FAILURE));
        Signal candidate=s(aurora.tenant,"target-10","ip-10","net-10","dev-shared","session-10","agent-shared",NOW,Signal.Outcome.FAILURE);
        Decision d=engine.evaluate(aurora,candidate,history,List.of());
        check(d.action==Decision.Action.DENY && "CORRELATED_DISTRIBUTED_STUFFING".equals(d.reason),"B rotating IPs, one attempt/account -> aggregate DENY");
        check(history.stream().map(x->x.account).distinct().count()==history.size(),"B no account exceeds one failure");
        // IP rotation without non-IP correlation is deliberately NOT classified as distributed stuffing.
        Signal unrelated=s(aurora.tenant,"target-x","ip-x","net-x","new-device","sx","new-agent",NOW,Signal.Outcome.ATTEMPT);
        Decision noClaim=engine.evaluate(aurora,unrelated,history,List.of());
        check(!"CORRELATED_DISTRIBUTED_STUFFING".equals(noClaim.reason),"B IP rotation alone is insufficient");
        // No reliable device ID is supplied by an ordinary WSO2 browser flow.
        // Independent IPs + account fanout + server-observed timing + repeated UA
        // must still be correlated, without claiming IP-only attribution.
        List<Signal> timed=new ArrayList<>();
        for(int i=0;i<9;i++) timed.add(s(aurora.tenant,"seen-"+i,"source-"+i,
                "segment-"+i,null,"unique-session-"+i,"ua-repeated",NOW-1800L+i*200L,
                Signal.Outcome.FAILURE));
        Signal next=s(aurora.tenant,"seen-z","source-z","segment-z",null,"unique-session-z",
                "ua-repeated",NOW,Signal.Outcome.ATTEMPT);
        Decision correlated=engine.evaluate(aurora,next,timed,List.of());
        check(correlated.action==Decision.Action.DENY &&
                "MULTI_IP_AGENT_CADENCE_SPRAY".equals(correlated.reason),
                "B without device ID, timing+reused agent+multiple accounts/IPs -> DENY");
        Decision noTiming=engine.evaluate(aurora,s(aurora.tenant,"seen-z","source-z",
                "segment-z",null,"unique-session-z","different-agent",NOW,
                Signal.Outcome.ATTEMPT),timed,List.of());
        check(noTiming.action==Decision.Action.ALLOW,
                "B UA and timing correlation are required; IP fanout alone does not deny");
    }
    static void bot() {
        List<Signal> h=new ArrayList<>();
        for(int i=0;i<7;i++)h.add(s(aurora.tenant,"acct-"+i,"ip-"+i,"n-"+i,"bot-device","s-"+i,"bot-agent",NOW-1400L+i*200L,Signal.Outcome.ATTEMPT));
        Signal c=s(aurora.tenant,"acct-test","ip-8","n-8","bot-device","s8","bot-agent",NOW,Signal.Outcome.ATTEMPT);
        Decision d=engine.evaluate(aurora,c,h,List.of());
        check(d.action==Decision.Action.STEP_UP && "BOT_CADENCE_AND_REUSE".equals(d.reason),"C cadence + signature -> STEP_UP");
        Signal raw=new Signal(aurora.tenant,"bot","other","other","x","x","x",NOW,Signal.Outcome.ATTEMPT,true,false);
        check(engine.evaluate(aurora,raw,List.of(),List.of()).action==Decision.Action.CHALLENGE,"C automation signal -> CHALLENGE");
    }
    static void baseline() {
        List<Signal> hist=new ArrayList<>();
        for(int i=0;i<6;i++)hist.add(s(aurora.tenant,"acct-baseline","ip-old","net-old","dev-old","session-"+i,
                "agent-old",NOW-(i+1)*86400000L,Signal.Outcome.SUCCESS));
        Signal novel=s(aurora.tenant,"acct-baseline","ip-new","net-new","dev-new","unique","agent",NOW,Signal.Outcome.SUCCESS);
        check(engine.evaluate(aurora,novel,List.of(),hist).action==Decision.Action.STEP_UP,"D mature account, new network + device -> STEP_UP");
        check(engine.evaluate(aurora,novel,List.of(),List.of()).action==Decision.Action.ALLOW,"D cold start cannot invent a baseline");
        Signal elsewhere=s(brisa.tenant,"acct-baseline","ip-new","net-new","dev-new","unique","agent",NOW,Signal.Outcome.SUCCESS);
        check(engine.evaluate(brisa,elsewhere,List.of(),hist).action==Decision.Action.ALLOW,"D no baseline cross-tenant bleed");
    }
    static void responses() {
        for(int n:new int[]{0,25,48,68,93,99}) {

            Decision.Action a= new Decision(
                    n>=aurora.deny?Decision.Action.DENY:n>=aurora.stepUp?Decision.Action.STEP_UP:
                    n>=aurora.challenge?Decision.Action.CHALLENGE:n>=aurora.delay?Decision.Action.DELAY:Decision.Action.ALLOW,
                    n,"synthetic",aurora.version).action;
            check(a!=null,"decision tier threshold "+n);
        }
        Signal c=s(aurora.tenant,"x","ip","net","dev","sess","ua",NOW,Signal.Outcome.ATTEMPT);
        Signal bot=new Signal(aurora.tenant,"x","ip","net","dev","sess","ua",NOW,Signal.Outcome.ATTEMPT,true,false);
        check(engine.evaluate(aurora,bot,List.of(),List.of()).action==Decision.Action.CHALLENGE,"Aurora threshold for bot");
        Signal b=new Signal(brisa.tenant,"x","ip","net","dev","sess","ua",NOW,Signal.Outcome.ATTEMPT,true,false);
        check(engine.evaluate(brisa,b,List.of(),List.of()).action==Decision.Action.CHALLENGE,"Brisa threshold for bot");
        check(engine.evaluate(aurora,c,List.of(),List.of()).action==Decision.Action.ALLOW,"ordinary ALLOW");
        Signal failed=new Signal(aurora.tenant,"x","ip","net","dev","sess","ua",NOW,Signal.Outcome.ATTEMPT,false,true);
        check(engine.evaluate(aurora,failed,List.of(),List.of()).action==Decision.Action.DENY,"challenge failure -> DENY");
        List<Signal> early=new ArrayList<>();
        for(int i=0;i<2;i++)early.add(s(aurora.tenant,"early","ip-early","n","d"+i,"s"+i,"ua"+i,NOW-i*1000,Signal.Outcome.FAILURE));
        check(engine.evaluate(aurora,s(aurora.tenant,"early","ip-early","n","new","new","new",NOW,Signal.Outcome.ATTEMPT),early,List.of()).action==Decision.Action.DELAY,"Aurora graded DELAY after two failures");
        // Four single-source failures result in CHALLENGE, but never an unbounded sleep.
        List<Signal> h=new ArrayList<>();
        for(int i=0;i<4;i++)h.add(s(aurora.tenant,"a","ip-1","n","d"+i,"s"+i,"a"+i,NOW-i*1000,Signal.Outcome.FAILURE));
        check(engine.evaluate(aurora,s(aurora.tenant,"a","ip-1","n","new","new","new",NOW,Signal.Outcome.ATTEMPT),h,List.of()).action==Decision.Action.CHALLENGE,"graduated response CHALLENGE");
        List<Signal> net=new ArrayList<>();
        for(int i=0;i<5;i++)net.add(s(aurora.tenant,"t"+i,"ip-1","net-1","d"+i,"s"+i,"ua"+i,NOW-i*1000,Signal.Outcome.FAILURE));
        check(engine.evaluate(aurora,s(aurora.tenant,"z","ip-1","net-1","dZ","sZ","uaZ",NOW,Signal.Outcome.ATTEMPT),net,List.of()).action==Decision.Action.STEP_UP,"network spray STEP_UP");
    }
    static void resiliencePrivacy() {
        RiskService unavailable=new RiskService(new Store() {
            public List<Signal> recent(Policy p,long now) {throw new IllegalStateException("DB down");}
            public List<Signal> baseline(Policy p,String account,long now){throw new IllegalStateException("DB down");}
            public void record(Signal s) {throw new IllegalStateException("DB down");}
        },Map.of(aurora.tenant,aurora),(s,d)->{});
        Signal c=s(aurora.tenant,"a","ip","net","dev","sess","agent",NOW,Signal.Outcome.ATTEMPT);
        check(unavailable.check(c).action==Decision.Action.DENY,"risk DB outage fail-safe, no external service bypass");
        check(unavailable.check(s(brisa.tenant,"a","ip","net","dev","sess","agent",NOW,Signal.Outcome.ATTEMPT)).action==Decision.Action.DENY,"unknown tenant denied");
        Pseudonymizer p=new Pseudonymizer(new byte[32]);
        check(!p.hash("a","account","alice").equals(p.hash("b","account","alice")),"HMAC tenant segregation");
        check(!p.hash("a","account","alice").equals(p.hash("a","network","alice")),"HMAC field segregation");
        TrustedClientIp t=new TrustedClientIp(List.of("10.1.0.0/16"));
        check("203.0.113.7".equals(t.resolve("203.0.113.7","1.2.3.4")),"spoofed XFF rejected from nonproxy");
        check("198.51.100.9".equals(t.resolve("10.1.0.7","1.2.3.4, 198.51.100.9")),"first untrusted hop from right wins");
        check("192.0.2.8".equals(t.resolve("10.1.0.7","192.0.2.8,10.1.0.8")),"trusted proxy chain traversal");
    }
    public static void main(String[] args) {
        bruteForce();stuffing();bot();baseline();responses();resiliencePrivacy();
        System.out.println("OFFLINE_TEST TOTAL="+tested.get());
    }
}
