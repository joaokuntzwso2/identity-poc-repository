import java.io.InputStream;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import javax.net.ssl.HttpsURLConnection;

/** Java truststore and Docker-DNS HTTPS probe executed INSIDE the WSO2 container.
 * Not a replacement for an application-registration/API readback.
 */
class SectorProbe {
    public static void main(String[] args) throws Exception {
        if (args.length != 1 || !args[0].matches("https://(?:aurora|brisa)-sector\\.identity\\.test/sector\\.json")) {
            throw new IllegalArgumentException("UNEXPECTED_SECTOR_URL");
        }
        var conn = (HttpsURLConnection) URI.create(args[0]).toURL().openConnection();
        conn.setConnectTimeout(10000);
        conn.setReadTimeout(10000);
        conn.setInstanceFollowRedirects(false);
        conn.setRequestProperty("Accept", "application/json");
        if (conn.getResponseCode() != 200) throw new IllegalStateException("SECTOR_NON_200");
        if (!String.valueOf(conn.getContentType()).toLowerCase().contains("json"))
            throw new IllegalStateException("SECTOR_WRONG_CONTENT_TYPE");
        try (InputStream stream = conn.getInputStream()) {
            byte[] bytes = stream.readNBytes(32769);
            if (bytes.length > 32768) throw new IllegalStateException("SECTOR_DOCUMENT_TOO_LARGE");
            System.out.print(new String(bytes, StandardCharsets.UTF_8));
        } finally { conn.disconnect(); }
    }
}
