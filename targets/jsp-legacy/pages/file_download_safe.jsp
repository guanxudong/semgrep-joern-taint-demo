<%@ page import="legacy.service.FileService" %>
<html>
<body>
<%-- SAFE: jsp-safe-04 (mimics path-traversal) - filename checked against an allow-list --%>
<%
    String name = request.getParameter("name");
    FileService fileService = new FileService();
    String content = fileService.readWhitelisted(name);
    out.print(content);
%>
</body>
</html>
