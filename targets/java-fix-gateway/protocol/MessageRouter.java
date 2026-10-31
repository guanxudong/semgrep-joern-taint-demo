package com.tradeflow.protocol;

import java.util.HashMap;
import java.util.Map;

/** Dispatches inbound FIX messages to registered handlers by MsgType (tag 35). */
public class MessageRouter {
    public interface Handler {
        Object handle(Session session, FixMessage msg) throws Exception;
    }

    private final Map<String, Handler> handlers = new HashMap<>();

    public void register(String msgType, Handler handler) {
        handlers.put(msgType, handler);
    }

    public Object dispatch(Session session, FixMessage msg) throws Exception {
        Handler handler = handlers.get(msg.getMsgType());
        if (handler == null) {
            return null;
        }
        return handler.handle(session, msg);
    }
}
