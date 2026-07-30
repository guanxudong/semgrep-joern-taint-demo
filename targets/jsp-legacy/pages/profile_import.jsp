<%@ page import="legacy.model.User, java.io.ByteArrayInputStream, java.io.ObjectInputStream, java.util.Base64" %>
<html>
<body>
<%-- VULN: jsp-deserialization-01 (deserialization, cwe-502) [medium] --%>
<%
    String b64 = request.getParameter("data");
    byte[] data = Base64.getDecoder().decode(b64);
    ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(data));
    User user = (User) ois.readObject();
    out.print("imported " + user.username);
%>
</body>
</html>
