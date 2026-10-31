using System.Data;
using System.Collections.Generic;

namespace TradeFlow.Services
{
    /** Market-data alert rule evaluation. */
    public class RuleEngine
    {
        private readonly DataTable _table = new DataTable();

        public object Evaluate(string expr, Dictionary<string, double> data)
        {
            return _table.Compute(expr, null);
        }
    }
}
