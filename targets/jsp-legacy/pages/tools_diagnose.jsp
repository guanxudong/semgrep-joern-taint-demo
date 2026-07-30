<%@ page import="legacy.service.ToolService" %>
<html>
<body>
<%-- VULN: jsp-cmdi-02 (cmdi, cwe-78) [deep, taint via instance field] --%>
<%
    String host = request.getParameter("host");
    ToolService toolService = new ToolService();
    toolService.stageTarget(host);
    out.print("rc=" + toolService.runStagedDiag());
%>
</body>
</html>
