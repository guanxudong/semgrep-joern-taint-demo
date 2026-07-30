<%@ page import="legacy.data.UserRepository, java.sql.ResultSet, java.util.ArrayList, java.util.List" %>
<html>
<body>
<%-- VULN: jsp-sqli-01 (sqli, cwe-89) [shallow] --%>
<%
    String q = request.getParameter("q");
    UserRepository repo = new UserRepository();
    ResultSet rs = repo.queryUnsafe("SELECT username FROM users WHERE username LIKE '%" + q + "%'");
    List<String> names = new ArrayList<String>();
    while (rs.next()) {
        names.add(rs.getString(1));
    }
%>
<h1>Search results</h1>
<ul>
<% for (String n : names) { %>
    <li><%= n %></li>
<% } %>
</ul>
</body>
</html>
