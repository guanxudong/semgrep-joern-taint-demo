<%@ page import="legacy.config.AppConfig" %>
<html>
<body>
<%-- VULN: jsp-auth-flaws-01 (auth-flaws, cwe-287) - predictable md5(username) reset token --%>
<%
    String username = request.getParameter("username");
    String token = AppConfig.resetToken(username);
    out.print("reset token: " + token);
%>
</body>
</html>
