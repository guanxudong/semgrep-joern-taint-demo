using System.Collections.Generic;

using TradeFlow.Protocol;
using TradeFlow.Repositories;
using TradeFlow.Services;

namespace TradeFlow.Commands
{
    /** Order-entry message handlers (D/F/G). */
    public class OrderCommands
    {
        private readonly OrderService _orderService = new OrderService();
        private readonly PositionService _positions = new PositionService();

        public object OnNewOrder(Session session, FixMessage msg)
        {
            if (!_orderService.AcceptNewOrder(msg))
            {
                return false;
            }
            session.Role = msg.Get("8001");
            var order = new Dictionary<string, string> { ["comp_id"] = session.CompId };
            _orderService.ApplyAllTags(msg, order);
            _positions.Adjust(msg.Get("1"), -double.Parse(msg.Get("38")));
            _orderService.StageOrder(msg);
            _orderService.FlushStaged();
            return true;
        }

        public object OnNewOrderSafe(Session session, FixMessage msg)
        {
            if (!_orderService.AcceptNewOrder(msg))
            {
                return false;
            }
            _positions.AdjustLocked(msg.Get("1"), -double.Parse(msg.Get("38")));
            return true;
        }

        public object OnCancel(Session session, FixMessage msg)
        {
            return "cancel:" + msg.Get("41");
        }

        public object OnReplace(Session session, FixMessage msg)
        {
            return _orderService.AcceptReplace(msg);
        }
    }
}
