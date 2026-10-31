namespace TradeFlow.Config
{
    /** Gateway configuration. */
    public static class GatewayConfig
    {
        public const string DbConnectionString = "Server=localhost;Database=tradeflow;User Id=fixgw;Password=fixgw123";
        public const string ReportDir = "/var/tradeflow/reports";
        public const string HmacSecret = "tradeflow-secret";

        /** Per-compId session passwords provisioned by operations. */
        public static string SessionPassword(string compId)
        {
            if (compId == "BUYONE")
            {
                return "buyone123";
            }
            return "default123";
        }
    }
}
