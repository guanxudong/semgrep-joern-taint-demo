using System.Collections.Generic;

using TradeFlow.Protocol;
using TradeFlow.Services;

namespace TradeFlow.Commands
{
    /** Administrative and reporting handlers. */
    public class AdminCommands
    {
        private readonly ReportService _reports = new ReportService();
        private readonly OpsService _ops = new OpsService();
        private readonly RefDataService _refData = new RefDataService();
        private readonly SessionStore _sessions = new SessionStore();
        private readonly NotifyService _notices = new NotifyService();

        public object OnAdmin(Session session, FixMessage msg)
        {
            return new Dictionary<string, string>
            {
                ["op"] = msg.Get("58"),
                ["scope"] = "gateway",
            };
        }

        public object OnExportReport(Session session, FixMessage msg)
        {
            var rows = new List<Dictionary<string, string>>
            {
                new Dictionary<string, string>
                {
                    ["symbol"] = msg.Get("55"),
                    ["qty"] = msg.Get("38"),
                },
            };
            var html = _reports.RenderBlotter(session.CompId, rows);
            _reports.ExportReport(msg.Get("58"), html);
            return html;
        }

        public object OnExportReportSafe(Session session, FixMessage msg)
        {
            _reports.ExportReportSafe(msg.Get("58"), "<html></html>");
            return true;
        }

        public object OnImportRefData(Session session, FixMessage msg)
        {
            return _refData.LoadRefData(msg.Get("10002"));
        }

        public object OnImportRefDataSafe(Session session, FixMessage msg)
        {
            return _refData.LoadRefDataSafe(msg.Get("10002"));
        }

        public object OnRestoreSession(Session session, FixMessage msg)
        {
            return _sessions.Restore(msg.Get("10003"));
        }

        public object OnNotice(Session session, FixMessage msg)
        {
            var ctx = new Dictionary<string, string>
            {
                ["symbol"] = msg.Get("55"),
                ["qty"] = msg.Get("38"),
            };
            return _notices.RenderNotice(msg.Get("10004"), ctx);
        }

        public object OnDiag(Session session, FixMessage msg)
        {
            _ops.NotifyOps(msg.Get("58"));
            return true;
        }
    }
}
