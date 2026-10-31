package com.tradeflow.commands;

import java.sql.ResultSet;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import com.tradeflow.protocol.FixMessage;
import com.tradeflow.protocol.Session;
import com.tradeflow.repositories.OrderRepository;

/** Order-status query handler (H). */
public class QueryCommands {
    private final OrderRepository repo = new OrderRepository();

    public Object onOrderQuery(Session session, FixMessage msg) throws Exception {
        ResultSet rs = repo.findByClOrdId(msg.get("11"));
        List<String> rows = new ArrayList<>();
        while (rs.next()) {
            rows.add(rs.getString("symbol"));
        }
        return rows;
    }

    public Object onOrderQuerySafe(Session session, FixMessage msg) throws Exception {
        ResultSet rs = repo.findForSessionSafe(session.getCompId(), msg.get("11"));
        List<String> rows = new ArrayList<>();
        while (rs.next()) {
            rows.add(rs.getString("symbol"));
        }
        return rows;
    }
}
