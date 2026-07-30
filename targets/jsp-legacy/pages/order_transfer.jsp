<%@ page import="legacy.service.OrderService" %>
<html>
<body>
<%-- VULN: jsp-business-logic-01 (business-logic, cwe-840) [medium] - negative amount accepted --%>
<%
    String src = request.getParameter("src");
    String dst = request.getParameter("dst");
    double amount = Double.parseDouble(request.getParameter("amount"));
    OrderService orderService = new OrderService();
    double balance = orderService.transfer(src, dst, amount);
    out.print("balance=" + balance);
%>
</body>
</html>
