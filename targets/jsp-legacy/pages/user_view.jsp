<%@ page import="legacy.service.UserService, java.sql.ResultSet" %>
<html>
<body>
<%-- VULN: jsp-idor-01 (idor, cwe-639) [medium] --%>
<%
    String id = request.getParameter("id");
    UserService userService = new UserService();
    ResultSet rs = userService.findById(id);
    if (rs.next()) {
        out.print("<p>" + rs.getString("username") + " / " + rs.getString("email") + "</p>");
    }
%>
</body>
</html>
