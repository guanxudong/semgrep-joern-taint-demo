<%@ page import="legacy.service.OrderService" %>
<html>
<body>
<%-- VULN: jsp-business-logic-01 (business-logic, cwe-840) - coupon never invalidated, reusable forever --%>
<%
    String user = request.getParameter("user");
    String coupon = request.getParameter("coupon");
    OrderService orderService = new OrderService();
    boolean ok = orderService.applyCoupon(user, coupon);
    out.print("applied=" + ok);
%>
</body>
</html>
