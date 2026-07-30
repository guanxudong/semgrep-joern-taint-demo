<%@ page import="legacy.data.UserRepository, java.sql.ResultSet" %>
<html>
<body>
<%-- VULN: jsp-broken-access-control-01 (broken-access-control, cwe-862) [shallow] - no auth or role check at all --%>
<%
    UserRepository repo = new UserRepository();
    ResultSet rs = repo.queryUnsafe("SELECT id, username, email, role FROM users");
    while (rs.next()) {
        out.print("<p>" + rs.getString("username") + " (" + rs.getString("role") + ")</p>");
    }
%>
</body>
</html>
