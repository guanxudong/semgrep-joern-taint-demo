using System.Collections.Generic;

namespace BadDemo.Services
{
    /// <summary>Order / wallet logic with deliberate business-logic and race flaws.</summary>
    public class OrderService
    {
        private static readonly Dictionary<string, double> Balances = new Dictionary<string, double>
        {
            { "alice", 1000.0 },
            { "bob", 1000.0 }
        };

        /// <summary>No validation of amount sign -> negative amount steals money.</summary>
        public double Transfer(string src, string dst, double amount)
        {
            Balances[src] = Balances.GetValueOrDefault(src) - amount;
            Balances[dst] = Balances.GetValueOrDefault(dst) + amount;
            return Balances[src];
        }

        /// <summary>Coupon is never marked as used -> unlimited reuse.</summary>
        public bool ApplyCoupon(string user, string coupon)
        {
            if (coupon == "SAVE50")
            {
                Balances[user] = Balances.GetValueOrDefault(user) + 50.0;
                return true;
            }
            return false;
        }

        /// <summary>Check-then-act without any lock -> race condition (TOCTOU).</summary>
        public bool Withdraw(string user, double amount)
        {
            var balance = Balances.GetValueOrDefault(user);
            if (balance >= amount)
            {
                // attacker fires many concurrent requests here
                Balances[user] = balance - amount;
                return true;
            }
            return false;
        }

        private static readonly object SyncRoot = new object();

        public bool WithdrawSafe(string user, double amount)
        {
            lock (SyncRoot)
            {
                var balance = Balances.GetValueOrDefault(user);
                if (balance >= amount)
                {
                    Balances[user] = balance - amount;
                    return true;
                }
                return false;
            }
        }
    }
}
