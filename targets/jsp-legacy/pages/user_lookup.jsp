<%@ page import="legacy.service.UserService, java.sql.ResultSet" %>
<html>
<body>
<%-- VULN: jsp-sqli-02 (sqli, cwe-89) [deep, taint via instance field] --%>
<%
    String name = request.getParameter("name");
    UserService userService = new UserService();
    userService.stageName(name);
    ResultSet rs = userService.findStaged();
    while (rs.next()) {
        out.print("<p>" + rs.getString("username") + " / " + rs.getString("email") + "</p>");
    }
%>
</body>
</html>
