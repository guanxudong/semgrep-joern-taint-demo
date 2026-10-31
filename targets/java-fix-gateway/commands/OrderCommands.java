package com.tradeflow.commands;

import java.util.HashMap;
import java.util.Map;

import com.tradeflow.protocol.FixMessage;
import com.tradeflow.protocol.Session;
import com.tradeflow.services.OrderService;
import com.tradeflow.services.PositionService;

/** Order-entry message handlers (D/F/G). */
public class OrderCommands {
    private final OrderService orderService = new OrderService();
    private final PositionService positions = new PositionService();

    public Object onNewOrder(Session session, FixMessage msg) throws Exception {
        if (!orderService.acceptNewOrder(msg)) {
            return false;
        }
        session.setRole(msg.get("8001"));
        Map<String, String> order = new HashMap<>();
        order.put("comp_id", session.getCompId());
        orderService.applyAllTags(msg, order);
        positions.adjust(msg.get("1"), -Double.parseDouble(msg.get("38")));
        orderService.stageOrder(msg);
        orderService.flushStaged();
        return true;
    }

    public Object onNewOrderSafe(Session session, FixMessage msg) throws Exception {
        if (!orderService.acceptNewOrder(msg)) {
            return false;
        }
        positions.adjustLocked(msg.get("1"), -Double.parseDouble(msg.get("38")));
        return true;
    }

    public Object onCancel(Session session, FixMessage msg) {
        return "cancel:" + msg.get("41");
    }

    public Object onReplace(Session session, FixMessage msg) {
        return orderService.acceptReplace(msg);
    }
}
