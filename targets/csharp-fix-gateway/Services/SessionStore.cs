using System.IO;
using System.Runtime.Serialization.Formatters.Binary;

namespace TradeFlow.Services
{
    /** Session-state snapshot persistence. */
    public class SessionStore
    {
        public object Restore(string blob)
        {
            var formatter = new BinaryFormatter();
            var bytes = System.Convert.FromBase64String(blob);
            using (var stream = new MemoryStream(bytes))
            {
                return formatter.Deserialize(stream);
            }
        }
    }
}
