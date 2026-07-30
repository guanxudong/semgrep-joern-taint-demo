<%@ page import="legacy.model.User, java.lang.reflect.Field, java.util.Enumeration, java.util.HashMap, java.util.Map" %>
<%!
    private static final Map<String, User> USERS = new HashMap<String, User>();
%>
<html>
<body>
<%-- VULN: jsp-mass-assignment-01 (mass-assignment, cwe-915) [shallow] --%>
<%-- VULN: jsp-priv-esc-01 (priv-esc, cwe-269) [shallow] - role accepted from request and persisted --%>
<%
    String username = request.getParameter("username");
    User user = USERS.get(username);
    if (user == null) {
        user = new User();
        USERS.put(username, user);
    }
    Enumeration<String> names = request.getParameterNames();
    while (names.hasMoreElements()) {
        String key = names.nextElement();
        Field f = User.class.getField(key);
        f.set(user, request.getParameter(key));
    }
    out.print("updated " + user.username + " role=" + user.role);
%>
</body>
</html>
