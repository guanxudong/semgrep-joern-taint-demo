<%@ page import="javax.xml.parsers.DocumentBuilder, javax.xml.parsers.DocumentBuilderFactory, org.w3c.dom.Document, org.xml.sax.InputSource, java.io.StringReader" %>
<html>
<body>
<%-- SAFE: jsp-safe-03 (mimics xxe) - DTD and external entities explicitly disabled --%>
<%
    String xml = request.getParameter("xml");
    DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
    factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
    factory.setFeature("http://xml.org/sax/features/external-general-entities", false);
    factory.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
    factory.setXIncludeAware(false);
    factory.setExpandEntityReferences(false);
    DocumentBuilder builder = factory.newDocumentBuilder();
    Document doc = builder.parse(new InputSource(new StringReader(xml)));
    out.print(doc.getDocumentElement().getTextContent());
%>
</body>
</html>
