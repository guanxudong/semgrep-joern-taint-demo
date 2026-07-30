<%@ page import="legacy.data.UserRepository" %>
<html>
<body>
<%-- VULN: jsp-broken-access-control-01 (broken-access-control, cwe-862) - delete with no auth or role check --%>
<%
    String id = request.getParameter("id");
    UserRepository repo = new UserRepository();
    repo.executeUnsafe("DELETE FROM users WHERE id = " + id);
    out.print("deleted " + id);
%>
</body>
</html>
