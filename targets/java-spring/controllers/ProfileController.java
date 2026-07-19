package com.baddemo.controllers;

import java.io.ByteArrayInputStream;
import java.io.ObjectInputStream;
import java.lang.reflect.Field;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/profile")
public class ProfileController {

    public static class User {
        public String username = "";
        public String email = "";
        public String role = "user";
    }

    private static final Map<String, User> USERS = new HashMap<>();

    // VULN: java-mass-assignment-01 (mass-assignment, cwe-915)
    // VULN: java-priv-esc-01 (priv-esc, cwe-269) - role accepted from body and persisted
    @PostMapping("/update")
    public User updateProfile(@RequestBody Map<String, Object> body) throws Exception {
        String username = (String) body.get("username");
        User user = USERS.computeIfAbsent(username, k -> new User());
        for (Map.Entry<String, Object> e : body.entrySet()) {
            Field f = User.class.getField(e.getKey());
            f.set(user, e.getValue());
        }
        return user;
    }

    // VULN: java-deserialization-01 (deserialization, cwe-502) [medium]
    @PostMapping("/import")
    public String importProfile(@RequestBody String b64) throws Exception {
        byte[] data = Base64.getDecoder().decode(b64);
        ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(data));
        User user = (User) ois.readObject();
        USERS.put(user.username, user);
        return "imported " + user.username;
    }
}
