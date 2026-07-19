package com.baddemo.data;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.Statement;

import com.baddemo.config.AppConfig;

/** Raw JDBC data access. The unsafe methods are the SQLi sinks. */
public class UserRepository {

    private Connection connect() throws Exception {
        return DriverManager.getConnection(AppConfig.DB_URL, AppConfig.DB_USER, AppConfig.DB_PASSWORD);
    }

    /** Sink: executes a SQL string built by callers via concatenation. */
    public ResultSet queryUnsafe(String sql) throws Exception {
        Statement stmt = connect().createStatement();
        return stmt.executeQuery(sql);
    }

    public void executeUnsafe(String sql) throws Exception {
        Statement stmt = connect().createStatement();
        stmt.executeUpdate(sql);
    }

    public ResultSet querySafe(String sql, String arg) throws Exception {
        PreparedStatement ps = connect().prepareStatement(sql);
        ps.setString(1, arg);
        return ps.executeQuery();
    }
}
