package com.magalu.wso2.risk;

import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

/** HMAC tenant- and field-separated identifiers; never persist raw account/device/IP. */
public final class Pseudonymizer {
    private final byte[] key;
    public Pseudonymizer(byte[] key) {
        if (key == null || key.length < 32) throw new IllegalArgumentException("HMAC key >=32 bytes required");
        this.key = key.clone();
    }
    public String hash(String tenant, String label, String raw) {
        if (raw == null || raw.isEmpty()) return null;
        if (raw.length() > 512) throw new IllegalArgumentException("oversized input");
        try {
            Mac m = Mac.getInstance("HmacSHA256");
            m.init(new SecretKeySpec(key, "HmacSHA256"));
            byte[] result = m.doFinal((tenant+"\u0000"+label+"\u0000"+raw).getBytes(StandardCharsets.UTF_8));
            StringBuilder out=new StringBuilder();
            for (int i=0;i<16;i++) out.append(String.format("%02x",result[i] & 0xff));
            return out.toString();
        } catch (GeneralSecurityException ex) { throw new IllegalStateException(ex); }
    }
}
