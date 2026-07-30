<html>
<body>
<%-- VULN: jsp-xss-01 (xss, cwe-79) [shallow] --%>
<%
    String name = request.getParameter("name");
    out.print("<h1>Hello " + name + "</h1>");
%>
</body>
</html>
