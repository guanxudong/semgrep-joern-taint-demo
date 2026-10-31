package com.tradeflow.services;

import java.io.File;
import java.io.FileWriter;
import java.util.List;
import java.util.Map;

import com.tradeflow.config.GatewayConfig;

/** Blotter HTML rendering and report export. */
public class ReportService {

    public String renderBlotter(String account, List<Map<String, String>> rows) {
        StringBuilder html = new StringBuilder("<h2>Blotter for " + account + "</h2>\n<table>\n");
        for (Map<String, String> row : rows) {
            html.append("<tr><td>").append(row.get("symbol"))
                    .append("</td><td>").append(row.get("qty")).append("</td></tr>\n");
        }
        html.append("</table>\n");
        return html.toString();
    }

    public void exportReport(String name, String html) throws Exception {
        File out = new File(GatewayConfig.REPORT_DIR, name);
        FileWriter writer = new FileWriter(out);
        writer.write(html);
        writer.close();
    }

    public void exportReportSafe(String name, String html) throws Exception {
        if (!name.matches("[A-Za-z0-9_.-]+")) {
            throw new IllegalArgumentException("illegal report name");
        }
        File out = new File(GatewayConfig.REPORT_DIR, name);
        FileWriter writer = new FileWriter(out);
        writer.write(html);
        writer.close();
    }
}
