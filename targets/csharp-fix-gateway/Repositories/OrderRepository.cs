using System.Data.SqlClient;

using TradeFlow.Config;

namespace TradeFlow.Repositories
{
    /** Raw ADO.NET order persistence. */
    public class OrderRepository
    {
        private SqlConnection Connect()
        {
            return new SqlConnection(GatewayConfig.DbConnectionString);
        }

        public SqlDataReader FindByClOrdId(string clOrdId)
        {
            var cmd = new SqlCommand(
                "SELECT * FROM orders WHERE cl_ord_id = '" + clOrdId + "'", Connect());
            return cmd.ExecuteReader();
        }

        public SqlDataReader FindByClOrdIdSafe(string clOrdId)
        {
            var cmd = new SqlCommand("SELECT * FROM orders WHERE cl_ord_id = @id", Connect());
            cmd.Parameters.AddWithValue("@id", clOrdId);
            return cmd.ExecuteReader();
        }

        public SqlDataReader FindForSessionSafe(string compId, string clOrdId)
        {
            var cmd = new SqlCommand(
                "SELECT * FROM orders WHERE comp_id = @comp AND cl_ord_id = @id", Connect());
            cmd.Parameters.AddWithValue("@comp", compId);
            cmd.Parameters.AddWithValue("@id", clOrdId);
            return cmd.ExecuteReader();
        }

        public void InsertOrder(string account, string symbol, double qty)
        {
            var cmd = new SqlCommand(
                "INSERT INTO orders (account, symbol, qty) VALUES ('"
                + account + "', '" + symbol + "', " + qty + ")", Connect());
            cmd.ExecuteNonQuery();
        }
    }
}
