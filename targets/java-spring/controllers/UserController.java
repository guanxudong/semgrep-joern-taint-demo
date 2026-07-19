package com.baddemo.controllers;

import java.sql.ResultSet;
import java.util.ArrayList;
import java.util.List;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import com.baddemo.data.UserRepository;
import com.baddemo.services.UserService;

@RestController
@RequestMapping("/users")
public class UserController {

    private final UserRepository repo = new UserRepository();
    private final UserService userService = new UserService();

    // VULN: java-sqli-01 (sqli, cwe-89) [shallow]
    @GetMapping("/search")
    public List<String> search(@RequestParam String q) throws Exception {
        ResultSet rs = repo.queryUnsafe("SELECT username FROM users WHERE username LIKE '%" + q + "%'");
        List<String> out = new ArrayList<>();
        while (rs.next()) {
            out.add(rs.getString(1));
        }
        return out;
    }

    // VULN: java-sqli-02 (sqli, cwe-89) [deep, taint via instance field]
    @GetMapping("/lookup")
    public List<String> lookup(@RequestParam String name) throws Exception {
        userService.stageName(name);
        ResultSet rs = userService.findStaged();
        List<String> out = new ArrayList<>();
        while (rs.next()) {
            out.add(rs.getString(1));
        }
        return out;
    }

    // VULN: java-idor-01 (idor, cwe-639)
    @GetMapping("/{id}")
    public ResultSet getUser(@PathVariable String id) throws Exception {
        return userService.findById(id);
    }

    // SAFE: java-safe-01 (mimics sqli) - parameterized query
    @GetMapping("/search_safe")
    public ResultSet searchSafe(@RequestParam String q) throws Exception {
        return repo.querySafe("SELECT username FROM users WHERE username LIKE ?", "%" + q + "%");
    }

    // SAFE: java-safe-02 (mimics idor) - ownership checked against caller identity
    @GetMapping("/me/{id}")
    public Object getOwnProfile(@PathVariable String id, @RequestHeader("X-User-Id") String sessionUser) throws Exception {
        if (!sessionUser.equals(id)) {
            return "forbidden";
        }
        return userService.findByIdSafe(id);
    }
}
