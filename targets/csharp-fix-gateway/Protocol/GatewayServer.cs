using TradeFlow.Commands;

namespace TradeFlow.Protocol
{
    /** Bootstrap: wires every message handler into the router. */
    public static class GatewayServer
    {
        public static MessageRouter BuildRouter()
        {
            var router = new MessageRouter();
            var session = new SessionCommands();
            var orders = new OrderCommands();
            var queries = new QueryCommands();
            var marketData = new MarketDataCommands();
            var admin = new AdminCommands();
            router.Register("A", session.OnLogon);
            router.Register("D", orders.OnNewOrder);
            router.Register("D_safe", orders.OnNewOrderSafe);
            router.Register("F", orders.OnCancel);
            router.Register("G", orders.OnReplace);
            router.Register("H", queries.OnOrderQuery);
            router.Register("H_safe", queries.OnOrderQuerySafe);
            router.Register("V", marketData.OnMdSubscribe);
            router.Register("V_rule", marketData.OnMdRule);
            router.Register("V_alert", marketData.OnMdAlert);
            router.Register("ADMIN_OP", admin.OnAdmin);
            router.Register("EXPORT_REPORT", admin.OnExportReport);
            router.Register("EXPORT_REPORT_safe", admin.OnExportReportSafe);
            router.Register("IMPORT_REFDATA", admin.OnImportRefData);
            router.Register("IMPORT_REFDATA_safe", admin.OnImportRefDataSafe);
            router.Register("RESTORE_SESSION", admin.OnRestoreSession);
            router.Register("SEND_NOTICE", admin.OnNotice);
            router.Register("DIAG", admin.OnDiag);
            return router;
        }
    }
}
