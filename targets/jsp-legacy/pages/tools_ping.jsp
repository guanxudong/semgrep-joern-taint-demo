<html>
<body>
<%-- VULN: jsp-cmdi-01 (cmdi, cwe-78) [shallow] --%>
<%
    String host = request.getParameter("host");
    Process p = Runtime.getRuntime().exec("ping -c 1 " + host);
    out.print("rc=" + p.waitFor());
%>
</body>
</html>
