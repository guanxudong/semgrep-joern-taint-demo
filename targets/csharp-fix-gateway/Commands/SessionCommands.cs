using TradeFlow.Protocol;
using TradeFlow.Services;

namespace TradeFlow.Commands
{
    /** Session logon handler (A). */
    public class SessionCommands
    {
        private readonly LoginService _loginService = new LoginService();

        public object OnLogon(Session session, FixMessage msg)
        {
            var ok = _loginService.Validate(msg.Get("49"), msg.Get("98"), msg.Get("10000"),
                msg.Get("75"));
            if (ok)
            {
                session.LastSeqNum = long.Parse(msg.Get("34"));
            }
            return ok;
        }
    }
}
