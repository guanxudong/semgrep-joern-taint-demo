<%@ page import="freemarker.template.Configuration, freemarker.template.Template, java.io.StringWriter, java.util.HashMap" %>
<html>
<body>
<%-- VULN: jsp-ssti-01 (ssti, cwe-1336) [medium] --%>
<%
    String tpl = request.getParameter("tpl");
    Configuration cfg = new Configuration(Configuration.VERSION_2_3_31);
    Template template = new Template("user-tpl", tpl, cfg);
    StringWriter sw = new StringWriter();
    template.process(new HashMap<String, Object>(), sw);
    out.print(sw.toString());
%>
</body>
</html>
