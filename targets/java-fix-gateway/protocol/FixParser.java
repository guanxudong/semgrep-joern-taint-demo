package com.tradeflow.protocol;

/** Parses newline-delimited tag=value payloads into FixMessage. */
public class FixParser {

    public FixMessage parse(String line) {
        FixMessage msg = new FixMessage();
        for (String field : line.trim().split("\\|")) {
            String[] kv = field.split("=", 2);
            if (kv.length == 2) {
                msg.put(kv[0].trim(), kv[1].trim());
            }
        }
        return msg;
    }
}
