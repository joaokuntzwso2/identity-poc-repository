package com.magalu.wso2.risk;

import java.net.InetAddress;
import java.util.List;
import java.util.ArrayList;

/** RFC-7239 Forwarded is deliberately not processed: only the configured XFF boundary.
 * A trusted edge MUST overwrite XFF; forged rightmost untrusted hop is never skipped.
 */
public final class TrustedClientIp {
    private final List<String> proxies;
    public TrustedClientIp(List<String> proxyCidrs) { this.proxies = List.copyOf(proxyCidrs); }
    public String resolve(String peer, String xForwardedFor) {
        if (!trusted(peer) || xForwardedFor == null || xForwardedFor.length() > 512) return valid(peer);
        String[] ips = xForwardedFor.split(",", -1);
        if (ips.length > 12) return valid(peer);
        String current = peer;
        for (int i=ips.length-1;i>=0;i--) {
            if (!trusted(current)) break;
            String ip = valid(ips[i].trim());
            if (ip == null) return valid(peer);
            current = ip;
        }
        return current;
    }
    private boolean trusted(String ip) {
        if (ip == null) return false;
        for (String cidr : proxies) {
            try {
                String[] p = cidr.split("/", -1);
                byte[] addr= parseLiteral(ip), net=parseLiteral(p[0]);
                if (addr == null || net == null || addr.length != net.length) continue;
                int bits=Integer.parseInt(p[1]);
                if (bits < 0 || bits > addr.length*8) continue;
                boolean match=true;
                for(int i=0;i<addr.length && bits>0;i++) {
                    int n=Math.min(8,bits),mask=(0xff <<(8-n)) &0xff;
                    if ((addr[i] & mask)!=(net[i] & mask)) { match=false; break; }
                    bits-=n;
                }
                if (match) return true;
            } catch (Exception ignored) { /* invalid cidr never grants trust */ }
        }
        return false;
    }
    private static String valid(String value) { return parseLiteral(value)==null?null:value; }
    private static byte[] parseLiteral(String raw) {
        if (raw==null || raw.isEmpty() || !raw.matches("[0-9a-fA-F:.]+")) return null;
        try {
            if (!raw.contains(":") && !raw.matches("(?:[0-9]{1,3}\\.){3}[0-9]{1,3}")) return null;
            if (!raw.contains(":")) {
                String[] p=raw.split("\\."); byte[] b=new byte[4];
                for(int i=0;i<4;i++) { int x=Integer.parseInt(p[i]); if(x>255) return null; b[i]=(byte)x; }
                return b;
            }
            InetAddress a=InetAddress.getByName(raw); return a.getAddress();
        } catch(Exception e) { return null; }
    }
    public static String network(String ip) {
        byte[] b = parseLiteral(ip);
        if (b==null) return null;
        if (b.length==4) return (b[0]&255)+"."+(b[1]&255)+"."+(b[2]&255)+".0/24";
        StringBuilder s=new StringBuilder();
        for(int i=0;i<6;i+=2) s.append(String.format("%02x%02x:",b[i]&255,b[i+1]&255));
        return s.toString()+"0000:0000:0000:0000:0000/48";
    }
}
