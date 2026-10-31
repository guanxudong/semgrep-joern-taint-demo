package com.tradeflow.commands;

import com.tradeflow.protocol.FixMessage;
import com.tradeflow.protocol.Session;
import com.tradeflow.services.LoginService;

/** Session logon handler (A). */
public class SessionCommands {
    private final LoginService loginService = new LoginService();

    public Object onLogon(Session session, FixMessage msg) throws Exception {
        boolean ok = loginService.validate(msg.get("49"), msg.get("98"), msg.get("10000"),
                msg.get("75"));
        if (ok) {
            session.setLastSeqNum(Long.parseLong(msg.get("34")));
        }
        return ok;
    }
}
