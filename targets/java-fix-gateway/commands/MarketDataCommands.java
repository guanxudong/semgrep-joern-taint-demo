package com.tradeflow.commands;

import java.util.HashMap;
import java.util.Map;

import com.tradeflow.protocol.FixMessage;
import com.tradeflow.protocol.Session;
import com.tradeflow.services.OpsService;
import com.tradeflow.services.RuleEngine;

/** Market-data subscription and alert handlers (V). */
public class MarketDataCommands {
    private final RuleEngine ruleEngine = new RuleEngine();
    private final OpsService ops = new OpsService();

    public Object onMdSubscribe(Session session, FixMessage msg) {
        Map<String, Object> sub = new HashMap<>();
        sub.put("comp_id", session.getCompId());
        sub.put("symbol", msg.get("55"));
        return sub;
    }

    public Object onMdRule(Session session, FixMessage msg) throws Exception {
        Map<String, Object> data = new HashMap<>();
        data.put("last", Double.parseDouble(msg.get("270")));
        return ruleEngine.evaluate(msg.get("10001"), data);
    }

    public Object onMdAlert(Session session, FixMessage msg) throws Exception {
        ops.stageAlert(msg.get("58"));
        ops.sendStagedAlert();
        return true;
    }
}
