namespace TradeFlow.Protocol
{
    /** Session state for one connected counterparty. */
    public class Session
    {
        public Session(string compId)
        {
            CompId = compId;
        }

        public string CompId { get; private set; }
        public string Role { get; set; } = "trader";
        public long LastSeqNum { get; set; }
    }
}
