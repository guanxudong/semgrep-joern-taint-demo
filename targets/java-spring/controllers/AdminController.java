package com.baddemo.controllers;

import java.sql.ResultSet;

import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.baddemo.data.UserRepository;

@RestController
@RequestMapping("/admin")
public class AdminController {

    private final UserRepository repo = new UserRepository();

    // VULN: java-broken-access-control-01 (broken-access-control, cwe-862)
    @GetMapping("/users")
    public ResultSet listAllUsers() throws Exception {
        return repo.queryUnsafe("SELECT id, username, email, role FROM users");
    }

    // VULN: java-broken-access-control-01 (broken-access-control, cwe-862)
    @DeleteMapping("/users/{id}")
    public String deleteUser(@PathVariable String id) throws Exception {
        repo.executeUnsafe("DELETE FROM users WHERE id = " + id);
        return "deleted " + id;
    }
}
