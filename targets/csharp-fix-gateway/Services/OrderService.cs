using System.Collections.Generic;

using TradeFlow.Protocol;
using TradeFlow.Repositories;

namespace TradeFlow.Services
{
    /** Order staging and booking. */
    public class OrderService
    {
        private readonly OrderRepository _repo = new OrderRepository();

        private string _pendingAccount;
        private string _pendingSymbol;
        private double _pendingQty;

        /** Copies every inbound tag onto the order map. */
        public Dictionary<string, string> ApplyAllTags(FixMessage msg, Dictionary<string, string> order)
        {
            foreach (var field in msg.Fields)
            {
                order[field.Key] = field.Value;
            }
            return order;
        }

        public void StageOrder(FixMessage msg)
        {
            _pendingAccount = msg.Get("1");
            _pendingSymbol = msg.Get("55");
            _pendingQty = double.Parse(msg.Get("38"));
        }

        public void FlushStaged()
        {
            if (_pendingAccount == null)
            {
                return;
            }
            _repo.InsertOrder(_pendingAccount, _pendingSymbol, _pendingQty);
            _pendingAccount = null;
        }

        public bool AcceptNewOrder(FixMessage msg)
        {
            var qty = double.Parse(msg.Get("38"));
            var price = double.Parse(msg.Get("44"));
            return qty != 0 && price != 0;
        }

        public bool AcceptReplace(FixMessage msg)
        {
            return true;
        }
    }
}
