package com.magalu.wso2.risk;

import org.osgi.framework.ServiceRegistration;
import org.graalvm.polyglot.HostAccess;
import org.graalvm.polyglot.Value;
import org.graalvm.polyglot.proxy.ProxyExecutable;
import org.osgi.service.component.ComponentContext;
import org.wso2.carbon.identity.application.authentication.framework.JsFunctionRegistry;
import org.wso2.carbon.identity.application.authentication.framework.config.model.graph.js.JsAuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.context.TransientObjectWrapper;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkConstants;
import org.wso2.carbon.identity.event.handler.AbstractEventHandler;

import javax.servlet.http.HttpServletRequest;
import java.io.FileInputStream;
import java.nio.file.Path;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.HashMap;
import java.util.Arrays;

/** OSGi DS component; the function runs synchronously IN WSO2 auth flow and is a hard gate.
 * WSO2 exact GA binary compatibility must be verified by build-extension.sh on the target image.
 */
public final class Wso2RiskComponent {
    private JsFunctionRegistry registry;
    private ServiceRegistration<?> eventRegistration;
    private RiskService service;
    private Pseudonymizer pseudonymizer;
    private TrustedClientIp network;
    private PgStore store;
    private AsyncAuditSink audit;

    public void setRegistry(JsFunctionRegistry registry) { this.registry=registry; }
    public void unsetRegistry(JsFunctionRegistry registry) { this.registry=null; }
    protected void activate(ComponentContext ctx) throws Exception {
        // Fail startup rather than install an ALLOW function without the shared store.
        String url = mandatory("MAGALU_RISK_JDBC_URL");
        String user = mandatory("MAGALU_RISK_JDBC_USER");
        String password = mandatory("MAGALU_RISK_JDBC_PASSWORD");
        byte[] hmac = Base64.getDecoder().decode(mandatory("MAGALU_RISK_HMAC_BASE64"));
        pseudonymizer=new Pseudonymizer(hmac);
        network=new TrustedClientIp(Arrays.asList(System.getenv().getOrDefault("MAGALU_TRUSTED_PROXY_CIDRS", "").split(",")));
        store=new PgStore(url,user,password,3);
        Map<String,Policy> policies=new HashMap<>();
        String root=mandatory("MAGALU_RISK_POLICY_DIR");
        for(String brand:List.of("aurora", "brisa")) {
            try(FileInputStream f=new FileInputStream(Path.of(root,brand+".properties").toFile())) {
                Policy p=Policy.load(f); policies.put(p.tenant,p);
            }
        }
        audit=new AsyncAuditSink(Path.of(mandatory("MAGALU_RISK_SPOOL_PATH")),2048);
        service=new RiskService(store,policies,audit);
        registry.register(JsFunctionRegistry.Subsystem.SEQUENCE_HANDLER,
                "magaluRiskCheck", new HostRiskFunction(this));
        eventRegistration=ctx.getBundleContext().registerService(AbstractEventHandler.class.getName(),
                new Wso2RiskEvents(network,this::eventSignal),null);
        System.out.println("MAGALU_RISK_ACTIVE tenants=aurora,brisa engine=GA-7.3 policy=external");
    }
    protected void deactivate(ComponentContext ctx) throws Exception {
        if(registry!=null)registry.deRegister(JsFunctionRegistry.Subsystem.SEQUENCE_HANDLER,"magaluRiskCheck");
        if(eventRegistration!=null)eventRegistration.unregister();
        if(audit!=null)audit.close();
        if(store!=null)store.close();
    }
    // WSO2 IS 7.3 GraalJS requires an executable guest-language proxy.
    // Reject invalid interop arguments; never default to ALLOW.
    private Object checkGraal(Value... args) {
        try {
            if (args == null || args.length != 2 || args[0] == null || args[1] == null
                    || !args[0].isProxyObject() || !args[1].isString()) {
                return "DENY";
            }
            Object proxy = args[0].asProxyObject();
            if (!(proxy instanceof JsAuthenticationContext)) {
                return "DENY";
            }
            return check((JsAuthenticationContext) proxy, args[1].asString());
        } catch (RuntimeException ex) {
            return "DENY";
        }
    }
    // MAGALU_HOST_CALLABLE_V2: WSO2 persistCurrentContext excludes host functions.
    // A named @Export class is executable with WSO2's HostAccess.EXPLICIT policy.
    // Unlike ProxyExecutable, this is a host object and will not be serialized
    // as a guest JavaScript callback without a source location.
    public static final class HostRiskFunction implements Wso2RiskFunction {
        private final Wso2RiskComponent owner;

        public HostRiskFunction(Wso2RiskComponent owner) {
            this.owner = owner;
        }

        @Override
        @HostAccess.Export
        public String magaluRiskCheck(JsAuthenticationContext context, String verifiedUsername) {
            return owner.check(context, verifiedUsername);
        }
    }
    private String check(JsAuthenticationContext context,String verifiedUsername) {
        try {
            AuthenticationContext c=context.getWrapped();
            String tenant=c.getTenantDomain();
            if(!allowedTenant(tenant) || verifiedUsername==null || verifiedUsername.isBlank())return "DENY";
            HttpServletRequest req=request(c);
            if(req==null)return "DENY";
            String ip=network.resolve(req.getRemoteAddr(),req.getHeader("X-Forwarded-For"));
            if(ip==null)return "DENY";
            // User agent is a weak signal, never a proof of a device or privilege.
            String userAgent=req.getHeader("User-Agent");
            if(userAgent!=null && userAgent.length()>256) userAgent=null;
            String sid=req.getSession(false)==null?null:req.getSession(false).getId();
            Signal s=signal(tenant,verifiedUsername,ip,null,sid,userAgent,Signal.Outcome.ATTEMPT);
            return service.check(s).action.name();
        } catch(Exception e) { return "DENY"; }
    }
    private void eventSignal(String tenant,String verifiedOrAttemptedUsername,String rawIp,
                             String agent,Signal.Outcome outcome) {
        if(service==null || !allowedTenant(tenant))return;
        // Input rawIp was resolved from a server-owned servlet request through trusted-proxy policy.
        if(rawIp==null)return;
        try {service.check(signal(tenant,verifiedOrAttemptedUsername,rawIp,null,null,agent,outcome));}
        catch(Exception ignored){ /* risk service itself fail safe and writes bounded alert */ }
    }
    private Signal signal(String tenant,String account,String ip,String device,String session,String agent,Signal.Outcome o) {
        return new Signal(tenant,
                pseudonymizer.hash(tenant,"account",account),
                pseudonymizer.hash(tenant,"ip",ip),
                pseudonymizer.hash(tenant,"network",TrustedClientIp.network(ip)),
                pseudonymizer.hash(tenant,"device",device),
                pseudonymizer.hash(tenant,"session",session),
                pseudonymizer.hash(tenant,"agent",agent),
                System.currentTimeMillis(),o,false,false);
    }
    static HttpServletRequest request(AuthenticationContext context) {
        Object p=context.getParameter(FrameworkConstants.RequestAttribute.HTTP_REQUEST);
        if(p==null) p=context.getProperty(FrameworkConstants.RequestAttribute.HTTP_REQUEST);
        if(p instanceof TransientObjectWrapper) p=((TransientObjectWrapper)p).getWrapped();
        return p instanceof HttpServletRequest?(HttpServletRequest)p:null;
    }
    private static boolean allowedTenant(String domain) {
        return "aurora.identity.test".equals(domain)||"brisa.identity.test".equals(domain);
    }
    private static String mandatory(String key) {
        String v=System.getenv(key);
        if(v==null || v.isBlank())throw new IllegalStateException("Missing risk environment setting: "+key);
        return v;
    }
}
