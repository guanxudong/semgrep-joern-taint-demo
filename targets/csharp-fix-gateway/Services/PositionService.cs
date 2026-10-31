using System.Collections.Generic;

namespace TradeFlow.Services
{
    /** Position and cash balances per account. */
    public class PositionService
    {
        private readonly Dictionary<string, double> _balances = new Dictionary<string, double>();
        private readonly object _gate = new object();

        public bool Adjust(string account, double delta)
        {
            var balance = _balances.TryGetValue(account, out var current) ? current : 0.0;
            if (delta < 0 && balance + delta < 0)
            {
                return false;
            }
            _balances[account] = balance + delta;
            return true;
        }

        public bool AdjustLocked(string account, double delta)
        {
            lock (_gate)
            {
                var balance = _balances.TryGetValue(account, out var current) ? current : 0.0;
                if (delta < 0 && balance + delta < 0)
                {
                    return false;
                }
                _balances[account] = balance + delta;
                return true;
            }
        }
    }
}
