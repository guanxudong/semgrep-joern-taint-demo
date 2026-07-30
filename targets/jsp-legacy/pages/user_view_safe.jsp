<%@ page import="legacy.service.UserService, java.sql.ResultSet" %>
<html>
<body>
<%-- SAFE: jsp-safe-02 (mimics idor) - ownership checked against the session uid --%>
<%
    String id = request.getParameter("id");
    String sessionUser = (String) session.getAttribute("uid");
    if (sessionUser == null || !sessionUser.equals(id)) {
        response.sendError(403);
    } else {
        UserService userService = new UserService();
        ResultSet rs = userService.findByIdSafe(id);
        if (rs.next()) {
            out.print("<p>" + rs.getString("username") + " / " + rs.getString("email") + "</p>");
        }
    }
%>
</body>
</html>
