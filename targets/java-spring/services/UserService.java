package com.baddemo.services;

import java.sql.ResultSet;

import com.baddemo.data.UserRepository;

/** User lookup logic; holds tainted input in an instance field between calls. */
public class UserService {

    private final UserRepository repo = new UserRepository();

    /** Tainted value staged by the controller (taint via field). */
    private String pendingName;

    public void stageName(String name) {
        this.pendingName = name;
    }

    /** Reads the staged field and reaches the sink (deep chain end). */
    public ResultSet findStaged() throws Exception {
        String sql = "SELECT id, username, email FROM users WHERE username = '" + this.pendingName + "'";
        return repo.queryUnsafe(sql);
    }

    public ResultSet findByName(String name) throws Exception {
        String sql = "SELECT id, username, email FROM users WHERE username = '" + name + "'";
        return repo.queryUnsafe(sql);
    }

    public ResultSet findById(String id) throws Exception {
        String sql = "SELECT id, username, email, role FROM users WHERE id = " + id;
        return repo.queryUnsafe(sql);
    }

    public ResultSet findByIdSafe(String id) throws Exception {
        return repo.querySafe("SELECT id, username, email, role FROM users WHERE id = ?", id);
    }
}
