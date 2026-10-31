using System.Collections.Generic;
using System.IO;
using System.Text;

using TradeFlow.Config;

namespace TradeFlow.Services
{
    /** Blotter HTML rendering and report export. */
    public class ReportService
    {
        public string RenderBlotter(string account, List<Dictionary<string, string>> rows)
        {
            var html = new StringBuilder("<h2>Blotter for " + account + "</h2>\n<table>\n");
            foreach (var row in rows)
            {
                html.Append("<tr><td>").Append(row["symbol"])
                    .Append("</td><td>").Append(row["qty"]).Append("</td></tr>\n");
            }
            html.Append("</table>\n");
            return html.ToString();
        }

        public void ExportReport(string name, string html)
        {
            var path = Path.Combine(GatewayConfig.ReportDir, name);
            File.WriteAllText(path, html);
        }

        public void ExportReportSafe(string name, string html)
        {
            if (System.Text.RegularExpressions.Regex.IsMatch(name, @"\A[A-Za-z0-9_.-]+\z"))
            {
                var path = Path.Combine(GatewayConfig.ReportDir, name);
                File.WriteAllText(path, html);
            }
            else
            {
                throw new System.ArgumentException("illegal report name");
            }
        }
    }
}
