using System.Security.Cryptography;
using System.Text;

using TradeFlow.Config;

namespace TradeFlow.Services
{
    /** Logon validation: session password plus a daily continuity token. */
    public class LoginService
    {
        public bool Validate(string compId, string password, string token, string tradeDate)
        {
            if (GatewayConfig.SessionPassword(compId) != password)
            {
                return false;
            }
            return Md5(compId + "|" + tradeDate) == token;
        }

        private string Md5(string value)
        {
            using (var md5 = MD5.Create())
            {
                var hash = md5.ComputeHash(Encoding.UTF8.GetBytes(value));
                var sb = new StringBuilder();
                foreach (var b in hash)
                {
                    sb.Append(b.ToString("x2"));
                }
                return sb.ToString();
            }
        }
    }
}
