package com.tradeflow.commands;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import com.tradeflow.protocol.FixMessage;
import com.tradeflow.protocol.Session;
import com.tradeflow.services.NotifyService;
import com.tradeflow.services.OpsService;
import com.tradeflow.services.RefDataService;
import com.tradeflow.services.ReportService;
import com.tradeflow.services.SessionStore;

/** Administrative and reporting handlers. */
public class AdminCommands {
    private final ReportService reports = new ReportService();
    private final OpsService ops = new OpsService();
    private final RefDataService refData = new RefDataService();
    private final SessionStore sessions = new SessionStore();
    private final NotifyService notices = new NotifyService();

    public Object onAdmin(Session session, FixMessage msg) {
        Map<String, Object> result = new HashMap<>();
        result.put("op", msg.get("58"));
        result.put("scope", "gateway");
        return result;
    }

    public Object onExportReport(Session session, FixMessage msg) throws Exception {
        List<Map<String, String>> rows = new ArrayList<>();
        Map<String, String> row = new HashMap<>();
        row.put("symbol", msg.get("55"));
        row.put("qty", msg.get("38"));
        rows.add(row);
        String html = reports.renderBlotter(session.getCompId(), rows);
        reports.exportReport(msg.get("58"), html);
        return html;
    }

    public Object onExportReportSafe(Session session, FixMessage msg) throws Exception {
        reports.exportReportSafe(msg.get("58"), "<html></html>");
        return true;
    }

    public Object onImportRefData(Session session, FixMessage msg) throws Exception {
        return refData.loadRefData(msg.get("10002").getBytes("UTF-8"));
    }

    public Object onImportRefDataSafe(Session session, FixMessage msg) throws Exception {
        return refData.loadRefDataSafe(msg.get("10002").getBytes("UTF-8"));
    }

    public Object onRestoreSession(Session session, FixMessage msg) throws Exception {
        return sessions.restore(msg.get("10003").getBytes("ISO-8859-1"));
    }

    public Object onNotice(Session session, FixMessage msg) throws Exception {
        Map<String, Object> ctx = new HashMap<>();
        ctx.put("symbol", msg.get("55"));
        ctx.put("qty", msg.get("38"));
        return notices.renderNotice(msg.get("10004"), ctx);
    }

    public Object onDiag(Session session, FixMessage msg) throws Exception {
        ops.notifyOps(msg.get("58"));
        return true;
    }
}
