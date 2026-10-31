package com.tradeflow.config;

/** Gateway configuration. */
public class GatewayConfig {
    public static final String DB_URL = "jdbc:mysql://localhost:3306/tradeflow";
    public static final String DB_USER = "fixgw";
    public static final String DB_PASSWORD = "fixgw123";
    public static final String REPORT_DIR = "/var/tradeflow/reports";
    public static final String HMAC_SECRET = "tradeflow-secret";

    /** Per-compId session passwords provisioned by operations. */
    public static String sessionPassword(String compId) {
        if ("BUYONE".equals(compId)) {
            return "buyone123";
        }
        return "default123";
    }
}
