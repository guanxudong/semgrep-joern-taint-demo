<%@ page import="legacy.service.OrderService" %>
<html>
<body>
<%-- VULN: jsp-race-condition-01 (race-condition, cwe-367) [medium] --%>
<%
    String user = request.getParameter("user");
    double amount = Double.parseDouble(request.getParameter("amount"));
    OrderService orderService = new OrderService();
    boolean ok = orderService.withdraw(user, amount);
    out.print("ok=" + ok);
%>
</body>
</html>
