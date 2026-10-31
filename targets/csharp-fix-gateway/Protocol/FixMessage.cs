using System.Collections.Generic;

namespace TradeFlow.Protocol
{
    /** A parsed FIX-style tag=value message. */
    public class FixMessage
    {
        private readonly Dictionary<string, string> _fields = new Dictionary<string, string>();

        public void Put(string tag, string value)
        {
            _fields[tag] = value;
        }

        public string Get(string tag)
        {
            return _fields.TryGetValue(tag, out var value) ? value : null;
        }

        public Dictionary<string, string> Fields
        {
            get { return _fields; }
        }

        public string MsgType
        {
            get { return _fields.TryGetValue("35", out var value) ? value : null; }
        }
    }
}
