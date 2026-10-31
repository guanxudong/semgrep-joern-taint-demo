using System.Xml;

namespace TradeFlow.Services
{
    /** Reference-data XML loading. */
    public class RefDataService
    {
        public XmlDocument LoadRefData(string xml)
        {
            var doc = new XmlDocument();
            doc.LoadXml(xml);
            return doc;
        }

        public XmlDocument LoadRefDataSafe(string xml)
        {
            var settings = new XmlReaderSettings
            {
                DtdProcessing = DtdProcessing.Prohibit,
                XmlResolver = null,
            };
            using (var reader = XmlReader.Create(new System.IO.StringReader(xml), settings))
            {
                var doc = new XmlDocument();
                doc.Load(reader);
                return doc;
            }
        }
    }
}
