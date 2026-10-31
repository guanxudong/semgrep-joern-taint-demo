using System.CodeDom.Compiler;
using System.Collections.Generic;
using System.Text;
using Microsoft.CSharp;

namespace TradeFlow.Services
{
    /** Renders {{ ... }} notice templates for counterparty messaging. */
    public class NotifyService
    {
        public string RenderNotice(string template, Dictionary<string, string> ctx)
        {
            var body = new StringBuilder();
            body.Append("public class NoticeTemplate { public string Render() { return ");
            var remainder = template;
            while (remainder.Length > 0)
            {
                var open = remainder.IndexOf("{{");
                if (open < 0)
                {
                    body.Append("\"").Append(remainder).Append("\"");
                    break;
                }
                body.Append("\"").Append(remainder.Substring(0, open)).Append("\" + ");
                var close = remainder.IndexOf("}}", open);
                var expr = remainder.Substring(open + 2, close - open - 2);
                body.Append("(").Append(expr).Append(") + ");
                remainder = remainder.Substring(close + 2);
            }
            body.Append("\"\"; } }");
            using (var provider = new CSharpCodeProvider())
            {
                var parameters = new CompilerParameters { GenerateInMemory = true };
                var results = provider.CompileAssemblyFromSource(parameters, body.ToString());
                var type = results.CompiledAssembly.GetType("NoticeTemplate");
                var instance = System.Activator.CreateInstance(type);
                return (string)type.InvokeMember("Render", System.Reflection.BindingFlags.InvokeMethod,
                    null, instance, null);
            }
        }
    }
}
