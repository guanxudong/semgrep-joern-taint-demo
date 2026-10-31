using System.Collections.Generic;

using TradeFlow.Protocol;
using TradeFlow.Repositories;

namespace TradeFlow.Commands
{
    /** Order-status query handler (H). */
    public class QueryCommands
    {
        private readonly OrderRepository _repo = new OrderRepository();

        public object OnOrderQuery(Session session, FixMessage msg)
        {
            var rows = new List<string>();
            var reader = _repo.FindByClOrdId(msg.Get("11"));
            while (reader.Read())
            {
                rows.Add(reader["symbol"].ToString());
            }
            return rows;
        }

        public object OnOrderQuerySafe(Session session, FixMessage msg)
        {
            var rows = new List<string>();
            var reader = _repo.FindForSessionSafe(session.CompId, msg.Get("11"));
            while (reader.Read())
            {
                rows.Add(reader["symbol"].ToString());
            }
            return rows;
        }
    }
}
