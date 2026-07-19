using System.IO;
using System.Xml;
using Microsoft.AspNetCore.Mvc;

namespace BadDemo.Controllers
{
    [ApiController]
    [Route("xml")]
    public class XmlController : ControllerBase
    {
        // VULN: cs-xxe-01 (xxe, cwe-611) [shallow]
        [HttpPost("parse")]
        public IActionResult Parse([FromBody] string xml)
        {
            var settings = new XmlReaderSettings
            {
                DtdProcessing = DtdProcessing.Parse,
                XmlResolver = new XmlUrlResolver()
            };
            using var reader = XmlReader.Create(new StringReader(xml), settings);
            var doc = new XmlDocument();
            doc.Load(reader);
            return Ok(doc.DocumentElement.InnerText);
        }

        // SAFE: cs-safe-03 (mimics xxe) - DTD prohibited
        [HttpPost("parse_safe")]
        public IActionResult ParseSafe([FromBody] string xml)
        {
            var settings = new XmlReaderSettings
            {
                DtdProcessing = DtdProcessing.Prohibit,
                XmlResolver = null
            };
            using var reader = XmlReader.Create(new StringReader(xml), settings);
            var doc = new XmlDocument();
            doc.Load(reader);
            return Ok(doc.DocumentElement.InnerText);
        }
    }
}
