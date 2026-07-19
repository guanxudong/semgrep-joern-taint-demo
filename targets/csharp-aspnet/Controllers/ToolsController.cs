using System.CodeDom.Compiler;
using System.Diagnostics;
using BadDemo.Services;
using Microsoft.AspNetCore.Mvc;

namespace BadDemo.Controllers
{
    [ApiController]
    [Route("tools")]
    public class ToolsController : ControllerBase
    {
        private readonly ToolService _toolService = new ToolService();

        // VULN: cs-cmdi-01 (cmdi, cwe-78) [shallow]
        [HttpGet("ping")]
        public IActionResult Ping([FromQuery] string host)
        {
            var proc = Process.Start("cmd.exe", "/c ping " + host);
            proc.WaitForExit();
            return Ok(proc.ExitCode);
        }

        // VULN: cs-cmdi-02 (cmdi, cwe-78) [deep, taint via instance field]
        [HttpGet("diagnose")]
        public IActionResult Diagnose([FromQuery] string host)
        {
            _toolService.StageTarget(host);
            return Ok(_toolService.RunStagedDiag());
        }

        // VULN: cs-rce-01 (rce, cwe-94) [shallow]
        [HttpPost("calc")]
        public IActionResult Calc([FromBody] CalcRequest req)
        {
            string source = "public static class Eval { public static object Run() { return " + req.Expr + "; } }";
            var provider = CodeDomProvider.CreateProvider("CSharp");
            var parms = new CompilerParameters { GenerateInMemory = true };
            var result = provider.CompileAssemblyFromSource(parms, source);
            var type = result.CompiledAssembly.GetType("Eval");
            object value = type.GetMethod("Run").Invoke(null, null);
            return Ok(value);
        }

        public class CalcRequest
        {
            public string Expr { get; set; } = "0";
        }
    }
}
