<html>
<body>
<%-- VULN: jsp-rce-01 (rce, cwe-94) [shallow] --%>
<%
    String expr = request.getParameter("expr");
    javax.script.ScriptEngine engine = new javax.script.ScriptEngineManager().getEngineByName("JavaScript");
    Object result = engine.eval(expr);
    out.print(String.valueOf(result));
%>
</body>
</html>
