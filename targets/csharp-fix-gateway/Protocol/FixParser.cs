namespace TradeFlow.Protocol
{
    /** Parses newline-delimited tag=value payloads into FixMessage. */
    public class FixParser
    {
        public FixMessage Parse(string line)
        {
            var msg = new FixMessage();
            foreach (var field in line.Trim().Split('|'))
            {
                var kv = field.Split('=');
                if (kv.Length == 2)
                {
                    msg.Put(kv[0].Trim(), kv[1].Trim());
                }
            }
            return msg;
        }
    }
}
