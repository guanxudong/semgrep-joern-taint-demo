package com.tradeflow.services;

import java.util.Map;

import javax.script.ScriptEngine;
import javax.script.ScriptEngineManager;

/** Renders ${...} notice templates for counterparty messaging. */
public class NotifyService {

    public String renderNotice(String template, Map<String, Object> ctx) throws Exception {
        ScriptEngine engine = new ScriptEngineManager().getEngineByName("javascript");
        for (Map.Entry<String, Object> entry : ctx.entrySet()) {
            engine.put(entry.getKey(), entry.getValue());
        }
        String js = "var t = `" + template + "`; t";
        return (String) engine.eval(js);
    }
}
