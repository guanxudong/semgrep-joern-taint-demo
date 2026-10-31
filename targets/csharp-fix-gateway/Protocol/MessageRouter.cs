using System;
using System.Collections.Generic;

namespace TradeFlow.Protocol
{
    public delegate object MessageHandler(Session session, FixMessage msg);

    /** Dispatches inbound FIX messages to registered handlers by MsgType (tag 35). */
    public class MessageRouter
    {
        private readonly Dictionary<string, MessageHandler> _handlers = new Dictionary<string, MessageHandler>();

        public void Register(string msgType, MessageHandler handler)
        {
            _handlers[msgType] = handler;
        }

        public object Dispatch(Session session, FixMessage msg)
        {
            if (_handlers.TryGetValue(msg.MsgType, out var handler))
            {
                return handler(session, msg);
            }
            return null;
        }
    }
}
