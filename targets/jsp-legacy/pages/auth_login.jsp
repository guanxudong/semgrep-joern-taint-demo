<%@ page import="com.auth0.jwt.JWT, com.auth0.jwt.algorithms.Algorithm, java.util.Date" %>
<%@ page import="legacy.config.AppConfig" %>
<html>
<body>
<%-- VULN: jsp-auth-flaws-01 (auth-flaws, cwe-287) [medium] - no lockout; any credentials issue a token --%>
<%
    String username = request.getParameter("username");
    String password = request.getParameter("password");
    Algorithm alg = Algorithm.HMAC256(AppConfig.JWT_SECRET);
    String token = JWT.create().withSubject(username).withClaim("role", "user")
            .withIssuedAt(new Date()).sign(alg);
    out.print(token);
%>
</body>
</html>
