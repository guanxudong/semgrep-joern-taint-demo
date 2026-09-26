using System.Collections.Generic;

namespace BadDemo.Services
{
    /// <summary>Order / wallet logic.</summary>
    public class OrderService
    {
        private static readonly Dictionary<string, double> Balances = new Dictionary<string, double>
        {
            { "alice", 1000.0 },
            { "bob", 1000.0 }
        };

        public double Transfer(string src, string dst, double amount)
        {
            Balances[src] = Balances.GetValueOrDefault(src) - amount;
            Balances[dst] = Balances.GetValueOrDefault(dst) + amount;
            return Balances[src];
        }

        public bool ApplyCoupon(string user, string coupon)
        {
            if (coupon == "SAVE50")
            {
                Balances[user] = Balances.GetValueOrDefault(user) + 50.0;
                return true;
            }
            return false;
        }

        /// <summary>Checks the balance, then deducts the requested amount.</summary>
        public bool Withdraw(string user, double amount)
        {
            var balance = Balances.GetValueOrDefault(user);
            if (balance >= amount)
            {
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
