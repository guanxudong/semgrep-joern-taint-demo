using System.Data.SqlClient;
using BadDemo.Config;

namespace BadDemo.Data
{
    /// <summary>Raw ADO.NET data access.</summary>
    public class UserRepository
    {
        private SqlConnection Connect()
        {
            return new SqlConnection(AppConfig.ConnectionString);
        }

        /// <summary>Executes a SQL string provided by callers.</summary>
        public SqlDataReader QueryUnsafe(string sql)
        {
            var conn = Connect();
            conn.Open();
            var cmd = new SqlCommand(sql, conn);
            return cmd.ExecuteReader();
        }

        public void ExecuteUnsafe(string sql)
        {
            var conn = Connect();
            conn.Open();
            var cmd = new SqlCommand(sql, conn);
            cmd.ExecuteNonQuery();
        }

        public SqlDataReader QuerySafe(string sql, string arg)
        {
            var conn = Connect();
            conn.Open();
            var cmd = new SqlCommand(sql, conn);
            cmd.Parameters.AddWithValue("@p1", arg);
            return cmd.ExecuteReader();
        }
    }
}
