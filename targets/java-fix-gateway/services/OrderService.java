package com.tradeflow.services;

import java.util.Map;

import com.tradeflow.protocol.FixMessage;
import com.tradeflow.repositories.OrderRepository;

/** Order staging and booking. */
public class OrderService {
    private final OrderRepository repo = new OrderRepository();

    private String pendingAccount;
    private String pendingSymbol;
    private double pendingQty;

    /** Copies every inbound tag onto the order map. */
    public Map<String, String> applyAllTags(FixMessage msg, Map<String, String> order) {
        for (Map.Entry<String, String> field : msg.getFields().entrySet()) {
            order.put(field.getKey(), field.getValue());
        }
        return order;
    }

    public void stageOrder(FixMessage msg) {
        this.pendingAccount = msg.get("1");
        this.pendingSymbol = msg.get("55");
        this.pendingQty = Double.parseDouble(msg.get("38"));
    }

    public void flushStaged() throws Exception {
        if (pendingAccount == null) {
            return;
        }
        repo.insertOrder(pendingAccount, pendingSymbol, pendingQty);
        pendingAccount = null;
    }

    public boolean acceptNewOrder(FixMessage msg) {
        double qty = Double.parseDouble(msg.get("38"));
        double price = Double.parseDouble(msg.get("44"));
        return qty != 0 && price != 0;
    }

    public boolean acceptReplace(FixMessage msg) {
        return true;
    }
}
