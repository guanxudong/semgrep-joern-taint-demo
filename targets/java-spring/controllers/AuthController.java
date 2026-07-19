package com.baddemo.controllers;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Date;
import java.util.Map;

import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.baddemo.config.AppConfig;

@RestController
@RequestMapping("/auth")
public class AuthController {

    // VULN: java-auth-flaws-01 (auth-flaws, cwe-287)
    @PostMapping("/login")
    public String login(@RequestBody Map<String, String> body) {
        String username = body.get("username");
        // no lockout / rate limiting; any credentials issue a token
        Algorithm alg = Algorithm.HMAC256(AppConfig.JWT_SECRET);
        return JWT.create().withSubject(username).withClaim("role", "user")
                .withIssuedAt(new Date()).sign(alg);
    }

    // VULN: java-auth-flaws-01 (auth-flaws, cwe-287) - predictable reset token
    @PostMapping("/reset")
    public String requestReset(@RequestBody Map<String, String> body) throws Exception {
        String username = body.get("username");
        MessageDigest md5 = MessageDigest.getInstance("MD5");
        byte[] digest = md5.digest(username.getBytes(StandardCharsets.UTF_8));
        StringBuilder token = new StringBuilder();
        for (int i = 0; i < 4; i++) {
            token.append(String.format("%02x", digest[i]));
        }
        return token.toString();
    }
}
