using System.Collections.Generic;

using TradeFlow.Protocol;
using TradeFlow.Services;

namespace TradeFlow.Commands
{
    /** Market-data subscription and alert handlers (V). */
    public class MarketDataCommands
    {
        private readonly RuleEngine _ruleEngine = new RuleEngine();
        private readonly OpsService _ops = new OpsService();

        public object OnMdSubscribe(Session session, FixMessage msg)
        {
            return new Dictionary<string, string>
            {
                ["comp_id"] = session.CompId,
                ["symbol"] = msg.Get("55"),
            };
        }

        public object OnMdRule(Session session, FixMessage msg)
        {
            var data = new Dictionary<string, double> { ["last"] = double.Parse(msg.Get("270")) };
            return _ruleEngine.Evaluate(msg.Get("10001"), data);
        }

        public object OnMdAlert(Session session, FixMessage msg)
        {
            _ops.StageAlert(msg.Get("58"));
            _ops.SendStagedAlert();
            return true;
        }
    }
}
