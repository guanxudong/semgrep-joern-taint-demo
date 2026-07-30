<%@ page import="legacy.data.UserRepository, java.sql.ResultSet" %>
<html>
<body>
<%-- SAFE: jsp-safe-01 (mimics sqli) - parameterized PreparedStatement --%>
<%
    String q = request.getParameter("q");
    UserRepository repo = new UserRepository();
    ResultSet rs = repo.querySafe("SELECT username FROM users WHERE username LIKE ?", "%" + q + "%");
    while (rs.next()) {
        out.print("<li>" + rs.getString(1) + "</li>");
    }
%>
</body>
</html>
