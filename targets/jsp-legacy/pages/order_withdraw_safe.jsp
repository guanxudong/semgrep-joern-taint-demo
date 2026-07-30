<%@ page import="legacy.service.OrderService" %>
<html>
<body>
<%-- SAFE: jsp-safe-05 (mimics race-condition) - withdrawal guarded by synchronized block --%>
<%
    String user = request.getParameter("user");
    double amount = Double.parseDouble(request.getParameter("amount"));
    OrderService orderService = new OrderService();
    boolean ok = orderService.withdrawSafe(user, amount);
    out.print("ok=" + ok);
%>
</body>
</html>
