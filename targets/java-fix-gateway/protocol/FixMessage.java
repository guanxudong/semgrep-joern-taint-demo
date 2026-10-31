package com.tradeflow.protocol;

import java.util.LinkedHashMap;
import java.util.Map;

/** A parsed FIX-style tag=value message. */
public class FixMessage {
    private final Map<String, String> fields = new LinkedHashMap<>();

    public void put(String tag, String value) {
        fields.put(tag, value);
    }

    public String get(String tag) {
        return fields.get(tag);
    }

    public Map<String, String> getFields() {
        return fields;
    }

    public String getMsgType() {
        return fields.get("35");
    }
}
