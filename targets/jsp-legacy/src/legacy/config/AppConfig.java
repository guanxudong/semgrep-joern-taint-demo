package legacy.config;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;

/** Application configuration. Secrets are hardcoded on purpose (demo target). */
public class AppConfig {
    // VULN: jsp-auth-flaws-01 (auth-flaws, cwe-287) - hardcoded weak JWT secret
    public static final String JWT_SECRET = "secret";
    public static final String DB_URL = "jdbc:mysql://localhost:3306/baddemo";
    public static final String DB_USER = "admin";
    public static final String DB_PASSWORD = "admin123";
    public static final String UPLOAD_DIR = "/var/www/uploads";

    // VULN: jsp-auth-flaws-01 (auth-flaws, cwe-287) - predictable md5(username) reset token
    public static String resetToken(String username) throws Exception {
        MessageDigest md5 = MessageDigest.getInstance("MD5");
        byte[] digest = md5.digest(username.getBytes(StandardCharsets.UTF_8));
        StringBuilder token = new StringBuilder();
        for (int i = 0; i < 4; i++) {
            token.append(String.format("%02x", digest[i]));
        }
        return token.toString();
    }
}
