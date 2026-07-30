<%@ page import="javax.xml.parsers.DocumentBuilder, javax.xml.parsers.DocumentBuilderFactory, org.w3c.dom.Document, org.xml.sax.InputSource, java.io.StringReader" %>
<html>
<body>
<%-- VULN: jsp-xxe-01 (xxe, cwe-611) [shallow] --%>
<%
    String xml = request.getParameter("xml");
    DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
    DocumentBuilder builder = factory.newDocumentBuilder();
    Document doc = builder.parse(new InputSource(new StringReader(xml)));
    out.print(doc.getDocumentElement().getTextContent());
%>
</body>
</html>
