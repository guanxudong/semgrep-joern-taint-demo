using System.Data.SqlClient;
using BadDemo.Data;

namespace BadDemo.Services
{
    /// <summary>User lookup logic; holds tainted input in an instance field between calls.</summary>
    public class UserService
    {
        private readonly UserRepository _repo = new UserRepository();

        /// <summary>Tainted value staged by the controller (taint via field).</summary>
        private string _pendingName = "";

        public void StageName(string name)
        {
            _pendingName = name;
        }

        /// <summary>Reads the staged field and reaches the sink (deep chain end).</summary>
        public SqlDataReader FindStaged()
        {
            var sql = "SELECT id, username, email FROM users WHERE username = '" + _pendingName + "'";
            return _repo.QueryUnsafe(sql);
        }

        public SqlDataReader FindById(string id)
        {
            var sql = "SELECT id, username, email, role FROM users WHERE id = " + id;
            return _repo.QueryUnsafe(sql);
        }

        public SqlDataReader FindByIdSafe(string id)
        {
            return _repo.QuerySafe("SELECT id, username, email, role FROM users WHERE id = @p1", id);
        }
    }
}
