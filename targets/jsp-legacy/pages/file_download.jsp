<%@ page import="legacy.service.FileService" %>
<html>
<body>
<%-- VULN: jsp-path-traversal-01 (path-traversal, cwe-22) [medium] --%>
<%
    String name = request.getParameter("name");
    FileService fileService = new FileService();
    String content = fileService.readUserFile(name);
    out.print(content);
%>
</body>
</html>
