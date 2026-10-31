package com.tradeflow.services;

import java.util.Map;

import javax.script.ScriptEngine;
import javax.script.ScriptEngineManager;

/** Market-data alert rule evaluation. */
public class RuleEngine {

    public Object evaluate(String expr, Map<String, Object> data) throws Exception {
        ScriptEngine engine = new ScriptEngineManager().getEngineByName("javascript");
        engine.put("data", data);
        return engine.eval(expr);
    }
}
