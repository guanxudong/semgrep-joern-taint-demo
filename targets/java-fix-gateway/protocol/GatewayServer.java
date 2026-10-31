package com.tradeflow.protocol;

import com.tradeflow.commands.AdminCommands;
import com.tradeflow.commands.MarketDataCommands;
import com.tradeflow.commands.OrderCommands;
import com.tradeflow.commands.QueryCommands;
import com.tradeflow.commands.SessionCommands;

/** Bootstrap: wires every message handler into the router. */
public class GatewayServer {

    public static MessageRouter buildRouter() {
        MessageRouter router = new MessageRouter();
        SessionCommands session = new SessionCommands();
        OrderCommands orders = new OrderCommands();
        QueryCommands queries = new QueryCommands();
        MarketDataCommands marketData = new MarketDataCommands();
        AdminCommands admin = new AdminCommands();
        router.register("A", session::onLogon);
        router.register("D", orders::onNewOrder);
        router.register("D_safe", orders::onNewOrderSafe);
        router.register("F", orders::onCancel);
        router.register("G", orders::onReplace);
        router.register("H", queries::onOrderQuery);
        router.register("H_safe", queries::onOrderQuerySafe);
        router.register("V", marketData::onMdSubscribe);
        router.register("V_rule", marketData::onMdRule);
        router.register("V_alert", marketData::onMdAlert);
        router.register("ADMIN_OP", admin::onAdmin);
        router.register("EXPORT_REPORT", admin::onExportReport);
        router.register("EXPORT_REPORT_safe", admin::onExportReportSafe);
        router.register("IMPORT_REFDATA", admin::onImportRefData);
        router.register("IMPORT_REFDATA_safe", admin::onImportRefDataSafe);
        router.register("RESTORE_SESSION", admin::onRestoreSession);
        router.register("SEND_NOTICE", admin::onNotice);
        router.register("DIAG", admin::onDiag);
        return router;
    }

    public static void main(String[] args) throws Exception {
        MessageRouter router = buildRouter();
        Session session = new Session("BUYONE");
        FixMessage msg = new FixParser().parse(String.join(" ", args));
        router.dispatch(session, msg);
    }
}
