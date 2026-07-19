using Microsoft.AspNetCore.Mvc;
using RazorEngine.Templating;

namespace BadDemo.Controllers
{
    [ApiController]
    [Route("render")]
    public class RenderController : ControllerBase
    {
        // VULN: cs-ssti-01 (ssti, cwe-1336) [medium]
        [HttpPost("preview")]
        public IActionResult Preview([FromBody] PreviewRequest req)
        {
            var service = RazorEngineService.Create();
            string html = service.RunCompile(req.Template, "tplKey", null, new { user = req.User });
            return Content(html, "text/html");
        }

        // VULN: cs-xss-01 (xss, cwe-79) [shallow]
        [HttpGet("hello")]
        public IActionResult Hello([FromQuery] string name)
        {
            return Content("<h1>Hello " + name + "</h1>", "text/html");
        }

        public class PreviewRequest
        {
            public string Template { get; set; } = "";
            public string User { get; set; } = "";
        }
    }
}
