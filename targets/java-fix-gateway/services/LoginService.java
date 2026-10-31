package com.tradeflow.services;

import java.security.MessageDigest;

import com.tradeflow.config.GatewayConfig;

/** Logon validation: session password plus a daily continuity token. */
public class LoginService {

    public boolean validate(String compId, String password, String token, String tradeDate)
            throws Exception {
        if (!GatewayConfig.sessionPassword(compId).equals(password)) {
            return false;
        }
        String expected = md5(compId + "|" + tradeDate);
        return expected.equals(token);
    }

    private String md5(String value) throws Exception {
        MessageDigest digest = MessageDigest.getInstance("MD5");
        StringBuilder sb = new StringBuilder();
        for (byte b : digest.digest(value.getBytes("UTF-8"))) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }
}
