package com.tradeflow.repositories;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.Statement;

import com.tradeflow.config.GatewayConfig;

/** Raw JDBC order persistence. */
public class OrderRepository {

    private Connection connect() throws Exception {
        return DriverManager.getConnection(GatewayConfig.DB_URL, GatewayConfig.DB_USER,
                GatewayConfig.DB_PASSWORD);
    }

    public ResultSet findByClOrdId(String clOrdId) throws Exception {
        Statement stmt = connect().createStatement();
        return stmt.executeQuery(
                "SELECT * FROM orders WHERE cl_ord_id = '" + clOrdId + "'");
    }

    public ResultSet findByClOrdIdSafe(String clOrdId) throws Exception {
        PreparedStatement ps = connect().prepareStatement(
                "SELECT * FROM orders WHERE cl_ord_id = ?");
        ps.setString(1, clOrdId);
        return ps.executeQuery();
    }

    public ResultSet findForSessionSafe(String compId, String clOrdId) throws Exception {
        PreparedStatement ps = connect().prepareStatement(
                "SELECT * FROM orders WHERE comp_id = ? AND cl_ord_id = ?");
        ps.setString(1, compId);
        ps.setString(2, clOrdId);
        return ps.executeQuery();
    }

    public void insertOrder(String account, String symbol, double qty) throws Exception {
        Statement stmt = connect().createStatement();
        stmt.executeUpdate("INSERT INTO orders (account, symbol, qty) VALUES ('"
                + account + "', '" + symbol + "', " + qty + ")");
    }
}
