# DockerUIinfo未授权访问漏洞

DockerUIinfo ｜ 未授权访问 ｜ —
- **指纹**：`"static/common/js/ui.js"`
- **请求**：`GET /docker-api-stream/info HTTP/1.1`

**Payload**
```
endpoint_version: v1.41
endpoint: unix:2375
```
- **响应特征**：200